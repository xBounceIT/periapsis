import {
  Alert,
  AlertDescription,
  AlertTitle,
} from "@periapsis/ui/components/ui/alert";
import { Badge } from "@periapsis/ui/components/ui/badge";
import { Button } from "@periapsis/ui/components/ui/button";
import { Checkbox } from "@periapsis/ui/components/ui/checkbox";
import { Input } from "@periapsis/ui/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@periapsis/ui/components/ui/table";
import { Textarea } from "@periapsis/ui/components/ui/textarea";
import {
  Archive,
  CheckCircle2,
  FlaskConical,
  GitBranch,
  History,
  Plus,
  RefreshCw,
  RotateCcw,
  ShieldAlert,
  Star,
} from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";

import { FormField } from "../components/form-field";
import {
  idempotencyKeyForPayload,
  type IdempotencyReference,
} from "../lib/payload-idempotency";
import {
  normalizeWorkflowSimulation,
  type ManagedWorkflow,
  type WorkflowConditionValue,
  type WorkflowDesign,
  type WorkflowKind,
  type WorkflowPermission,
  type WorkflowSimulationFact,
  type WorkflowSimulationResult,
  type WorkflowVersion,
  WorkflowInputError,
} from "./model";
import {
  WorkflowApiError,
  type VersionedWorkflow,
  type WorkflowAdministrationApi,
} from "./workflow-api";
import {
  WorkflowEditor,
  workflowDraftFrom,
  type WorkflowDraft,
} from "./workflow-editor";
// oxlint-disable-next-line import/no-unassigned-import -- Vite extracts this module-owned stylesheet.
import "./workflows.css";

type InventoryState =
  | { kind: "error"; message: string }
  | { kind: "loading" }
  | {
      items: ManagedWorkflow[];
      kind: "ready";
      loadError: string | null;
      loadingMore: boolean;
      nextCursor?: string;
    };

type DetailState =
  | { kind: "error"; message: string }
  | { kind: "idle" }
  | { kind: "loading" }
  | { kind: "ready"; resource: VersionedWorkflow };

interface OperationFailure {
  message: string;
  reloadable: boolean;
  title: string;
}

interface WorkflowWorkspaceProps {
  api: WorkflowAdministrationApi;
  canManage: boolean;
  canRead: boolean;
  csrfToken: string;
  tenantId: string;
}

export function WorkflowWorkspace({
  api,
  canManage,
  canRead,
  csrfToken,
  tenantId,
}: WorkflowWorkspaceProps): React.JSX.Element {
  const [kind, setKind] = useState<WorkflowKind>("alert");
  const [inventory, setInventory] = useState<InventoryState>({
    kind: "loading",
  });
  const [detail, setDetail] = useState<DetailState>({ kind: "idle" });
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [draft, setDraft] = useState<WorkflowDraft>(() =>
    workflowDraftFrom("alert"),
  );
  const [creating, setCreating] = useState(false);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [operationError, setOperationError] = useState<OperationFailure | null>(
    null,
  );
  const inventoryGeneration = useRef(0);
  const inventoryRef = useRef(inventory);
  inventoryRef.current = inventory;
  const detailGeneration = useRef(0);
  const mutationGeneration = useRef(0);
  const mutationInFlight = useRef(false);
  const idempotency = useRef<Record<string, IdempotencyReference>>({});
  const contextKey = `${tenantId}\u0000${kind}\u0000${canRead ? "read" : "denied"}`;
  const contextKeyRef = useRef(contextKey);
  contextKeyRef.current = contextKey;
  const settledContextKey = useRef(contextKey);
  const selectedIdRef = useRef(selectedId);
  selectedIdRef.current = selectedId;

  const loadInventory = useCallback(
    async (signal?: AbortSignal, after?: string): Promise<void> => {
      const generation = ++inventoryGeneration.current;
      const expectedContextKey = contextKey;
      const previous =
        after !== undefined &&
        inventoryRef.current.kind === "ready" &&
        inventoryRef.current.nextCursor === after
          ? inventoryRef.current
          : undefined;
      if (after !== undefined && previous === undefined) return;
      setInventory(
        previous
          ? { ...previous, loadError: null, loadingMore: true }
          : { kind: "loading" },
      );
      try {
        const page = await api.list({
          ...(after === undefined ? {} : { after }),
          kind,
          limit: 100,
          signal,
          status: undefined,
          tenantId,
        });
        if (
          signal?.aborted ||
          generation !== inventoryGeneration.current ||
          contextKeyRef.current !== expectedContextKey
        )
          return;
        const pageItems = validateInventory(page.items, tenantId, kind);
        if (
          after !== undefined &&
          (page.nextCursor === after ||
            (page.nextCursor !== undefined && pageItems.length === 0))
        ) {
          throw new WorkflowInputError(
            "The workflow catalog cursor did not make progress.",
          );
        }
        const items = validateInventory(
          previous ? [...previous.items, ...pageItems] : pageItems,
          tenantId,
          kind,
        );
        setInventory({
          items,
          kind: "ready",
          loadError: null,
          loadingMore: false,
          ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
        });
        if (
          selectedIdRef.current &&
          !items.some((workflow) => workflow.id === selectedIdRef.current) &&
          page.nextCursor === undefined
        ) {
          setSelectedId(null);
          setDetail({ kind: "idle" });
        }
      } catch (caught: unknown) {
        if (
          signal?.aborted ||
          generation !== inventoryGeneration.current ||
          contextKeyRef.current !== expectedContextKey
        )
          return;
        const message = workflowErrorMessage(caught);
        setInventory(
          previous
            ? { ...previous, loadError: message, loadingMore: false }
            : { kind: "error", message },
        );
      }
    },
    [api, contextKey, kind, tenantId],
  );

  useEffect(() => {
    settledContextKey.current = contextKey;
    inventoryGeneration.current += 1;
    detailGeneration.current += 1;
    mutationGeneration.current += 1;
    mutationInFlight.current = false;
    setSelectedId(null);
    setDetail({ kind: "idle" });
    setCreating(false);
    setNotice(null);
    setOperationError(null);
    setBusy(false);
    setDraft(workflowDraftFrom(kind));
    const controller = new AbortController();
    if (canRead && tenantId) void loadInventory(controller.signal);
    return () => controller.abort();
  }, [canRead, contextKey, kind, loadInventory, tenantId]);

  const selectWorkflow = useCallback(
    async (workflowId: string): Promise<void> => {
      const generation = ++detailGeneration.current;
      const expectedContextKey = contextKey;
      setSelectedId(workflowId);
      setCreating(false);
      setNotice(null);
      setOperationError(null);
      setDetail({ kind: "loading" });
      try {
        const resource = validateVersionedWorkflow(
          await api.get({ tenantId, workflowId }),
          tenantId,
          workflowId,
          kind,
        );
        if (
          generation !== detailGeneration.current ||
          contextKeyRef.current !== expectedContextKey
        )
          return;
        setDetail({ kind: "ready", resource });
        setDraft(workflowDraftFrom(kind, resource.value));
      } catch (caught: unknown) {
        if (
          generation !== detailGeneration.current ||
          contextKeyRef.current !== expectedContextKey
        )
          return;
        setDetail({
          kind: "error",
          message: workflowErrorMessage(caught),
        });
      }
    },
    [api, contextKey, kind, tenantId],
  );

  if (!canRead || !tenantId) {
    return (
      <section className="workflow-denied" aria-labelledby="workflow-denied">
        <Alert variant="destructive">
          <ShieldAlert aria-hidden="true" />
          <AlertTitle id="workflow-denied">
            Workflow authority required
          </AlertTitle>
          <AlertDescription>
            An active tenant and live workflow.read authority are required. The
            API rechecks every read and mutation independently.
          </AlertDescription>
        </Alert>
      </section>
    );
  }

  if (settledContextKey.current !== contextKey) {
    return (
      <section className="workflow-workspace">
        <p role="status">Switching workflow tenant context…</p>
      </section>
    );
  }

  const current = detail.kind === "ready" ? detail.resource : undefined;

  async function mutate(
    operation: string,
    payload: unknown,
    action: (key: string) => Promise<VersionedWorkflow>,
    success: string,
    validateResult?: (result: VersionedWorkflow) => void,
  ): Promise<void> {
    if (mutationInFlight.current || !canManage) return;
    const generation = ++mutationGeneration.current;
    mutationInFlight.current = true;
    const expectedContextKey = contextKey;
    setBusy(true);
    setNotice(null);
    setOperationError(null);
    let mutationResponseReceived = false;
    try {
      const reference =
        idempotency.current[operation] ??
        (idempotency.current[operation] = { current: null });
      const rawResult = await action(
        idempotencyKeyForPayload(reference, payload),
      );
      mutationResponseReceived = true;
      const result = validateVersionedWorkflow(
        rawResult,
        tenantId,
        undefined,
        kind,
      );
      validateResult?.(result);
      reference.current = null;
      if (
        generation !== mutationGeneration.current ||
        contextKeyRef.current !== expectedContextKey
      ) {
        return;
      }
      let displayedResult = result;
      let replayRefreshFailure: OperationFailure | null = null;
      if (result.replayed) {
        try {
          const latest = validateVersionedWorkflow(
            await api.get({ tenantId, workflowId: result.value.id }),
            tenantId,
            result.value.id,
            kind,
          );
          requireNonRegressingReplayRefresh(result.value, latest.value);
          displayedResult = latest;
        } catch {
          replayRefreshFailure = {
            message:
              "The replay was confirmed, but the current workflow revision could not be reloaded. Reload before making another change.",
            reloadable: true,
            title: "Replay needs refresh",
          };
        }
      }
      if (
        generation !== mutationGeneration.current ||
        contextKeyRef.current !== expectedContextKey
      ) {
        return;
      }
      setSelectedId(displayedResult.value.id);
      setCreating(false);
      setDetail({ kind: "ready", resource: displayedResult });
      setDraft(workflowDraftFrom(kind, displayedResult.value));
      setNotice(result.replayed ? `${success} (safe replay).` : `${success}.`);
      setOperationError(replayRefreshFailure);
      await loadInventory();
    } catch (caught: unknown) {
      if (
        generation !== mutationGeneration.current ||
        contextKeyRef.current !== expectedContextKey
      ) {
        return;
      }
      setOperationError({
        message: workflowErrorMessage(caught),
        reloadable:
          mutationResponseReceived ||
          (caught instanceof WorkflowApiError &&
            (caught.code === "projection_mismatch" ||
              caught.status === 409 ||
              caught.status === 412)),
        title: "Operation failed",
      });
      throw caught;
    } finally {
      if (generation === mutationGeneration.current) {
        mutationInFlight.current = false;
        setBusy(false);
      }
    }
  }

  async function createWorkflow(input: {
    kind: WorkflowKind;
    key: string;
    displayName: string;
    description: string;
    design: WorkflowDesign;
  }): Promise<void> {
    const payload = { operation: "create", tenantId, ...input };
    await mutate(
      "create",
      payload,
      (key) =>
        api.create({
          body: input,
          csrfToken,
          idempotencyKey: key,
          tenantId,
        }),
      "Workflow lineage created",
    );
  }

  async function publishWorkflow(design: WorkflowDesign): Promise<void> {
    if (!current) return;
    const body = {
      design,
      expectedRevision: current.value.revision,
    };
    await mutate(
      `publish:${current.value.id}`,
      { body, etag: current.etag, operation: "publish", tenantId },
      (key) =>
        api.publish({
          body,
          csrfToken,
          etag: current.etag,
          idempotencyKey: key,
          tenantId,
          workflowId: current.value.id,
        }),
      "Immutable workflow version published",
      (result) => {
        if (result.value.currentVersion !== current.value.currentVersion + 1) {
          throw new WorkflowInputError(
            "The publication did not advance exactly one immutable version.",
          );
        }
      },
    );
  }

  async function updateMetadata(input: {
    displayName: string;
    description: string;
  }): Promise<void> {
    if (!current) return;
    const body = { ...input, expectedRevision: current.value.revision };
    await mutate(
      `metadata:${current.value.id}`,
      { body, etag: current.etag, operation: "metadata", tenantId },
      (key) =>
        api.updateMetadata({
          body,
          csrfToken,
          etag: current.etag,
          idempotencyKey: key,
          tenantId,
          workflowId: current.value.id,
        }),
      "Workflow metadata updated",
      (result) => requireUnchangedPublication(current.value, result.value),
    );
  }

  async function lifecycle(
    action: "archive" | "restore" | "setDefault",
  ): Promise<void> {
    if (!current) return;
    const body = { expectedRevision: current.value.revision };
    const input = {
      body,
      csrfToken,
      etag: current.etag,
      idempotencyKey: "",
      tenantId,
      workflowId: current.value.id,
    };
    const label =
      action === "archive"
        ? "Workflow archived"
        : action === "restore"
          ? "Workflow restored"
          : "Default workflow changed";
    await mutate(
      `${action}:${current.value.id}`,
      { body, etag: current.etag, operation: action, tenantId },
      (key) => api[action]({ ...input, idempotencyKey: key }),
      label,
      (result) => requireUnchangedPublication(current.value, result.value),
    ).catch(() => undefined);
  }

  return (
    <section className="workflow-workspace" aria-labelledby="workflow-title">
      <header className="workflow-workspace__heading">
        <div>
          <p className="section-label">Governed ticket state machines</p>
          <h1 id="workflow-title">Workflow foundry</h1>
          <p>
            Review, simulate, and publish immutable Alert and Case definitions.
            Existing tickets remain pinned to their original version.
          </p>
        </div>
        <div className="workflow-workspace__authority">
          <GitBranch aria-hidden="true" />
          <span>Live tenant boundary</span>
          <strong>{kind === "alert" ? "Alert" : "Case"} workflow</strong>
          <div>
            <Badge variant="outline">workflow.read</Badge>
            {canManage ? (
              <Badge variant="outline">workflow.manage</Badge>
            ) : null}
          </div>
        </div>
      </header>

      <div className="workflow-kind-switch" role="tablist" aria-label="Kind">
        {(["alert", "case"] as const).map((candidate) => (
          <button
            key={candidate}
            type="button"
            role="tab"
            aria-selected={kind === candidate}
            onClick={() => setKind(candidate)}
          >
            {candidate === "alert" ? "Alert workflow" : "Case workflow"}
          </button>
        ))}
      </div>

      {notice ? (
        <Alert className="workflow-notice">
          <CheckCircle2 aria-hidden="true" />
          <AlertTitle>Committed</AlertTitle>
          <AlertDescription>{notice}</AlertDescription>
        </Alert>
      ) : null}
      {operationError ? (
        <Alert variant="destructive">
          <ShieldAlert aria-hidden="true" />
          <AlertTitle>{operationError.title}</AlertTitle>
          <AlertDescription>
            <span>{operationError.message}</span>
            {operationError.reloadable ? (
              <Button
                type="button"
                variant="outline"
                disabled={busy}
                onClick={() => {
                  if (current) void selectWorkflow(current.value.id);
                  else void loadInventory();
                }}
              >
                <RefreshCw aria-hidden="true" />
                {current ? "Reload latest revision" : "Reload catalog"}
              </Button>
            ) : null}
          </AlertDescription>
        </Alert>
      ) : null}

      <div className="workflow-console">
        <WorkflowInventory
          canManage={canManage}
          inventory={inventory}
          kind={kind}
          selectedId={selectedId}
          onCreate={() => {
            detailGeneration.current += 1;
            setCreating(true);
            setSelectedId(null);
            setDetail({ kind: "idle" });
            setDraft(workflowDraftFrom(kind));
            setNotice(null);
            setOperationError(null);
          }}
          onRefresh={() => void loadInventory()}
          onLoadMore={(cursor) => void loadInventory(undefined, cursor)}
          onSelect={(id) => void selectWorkflow(id)}
        />

        <div className="workflow-console__main">
          {creating ? (
            <WorkflowEditor
              key={`create:${kind}`}
              busy={busy}
              canManage={canManage}
              draft={draft}
              setDraft={setDraft}
              onCreate={createWorkflow}
              onPublish={async () => undefined}
              onUpdateMetadata={async () => undefined}
            />
          ) : detail.kind === "loading" ? (
            <WorkflowLoading />
          ) : detail.kind === "error" ? (
            <WorkflowFailure message={detail.message} />
          ) : current ? (
            <>
              <div className="workflow-lifecycle">
                <div>
                  <Badge
                    variant={
                      current.value.status === "active"
                        ? "secondary"
                        : "outline"
                    }
                  >
                    {current.value.status}
                  </Badge>
                  {current.value.isDefault ? (
                    <Badge variant="outline">default</Badge>
                  ) : null}
                  <span>revision {current.value.revision}</span>
                </div>
                {canManage ? (
                  <div>
                    {!current.value.isDefault &&
                    current.value.status === "active" ? (
                      <Button
                        type="button"
                        variant="outline"
                        disabled={busy}
                        onClick={() => void lifecycle("setDefault")}
                      >
                        <Star aria-hidden="true" /> Set default
                      </Button>
                    ) : null}
                    {current.value.status === "active" ? (
                      <Button
                        type="button"
                        variant="outline"
                        disabled={busy || current.value.isDefault}
                        onClick={() => void lifecycle("archive")}
                      >
                        <Archive aria-hidden="true" /> Archive
                      </Button>
                    ) : (
                      <Button
                        type="button"
                        variant="outline"
                        disabled={busy}
                        onClick={() => void lifecycle("restore")}
                      >
                        <RotateCcw aria-hidden="true" /> Restore
                      </Button>
                    )}
                  </div>
                ) : null}
              </div>
              <WorkflowEditor
                key={`${current.value.id}:${current.value.revision}`}
                busy={busy}
                canManage={canManage}
                draft={draft}
                resource={current.value}
                setDraft={setDraft}
                onCreate={createWorkflow}
                onPublish={publishWorkflow}
                onUpdateMetadata={updateMetadata}
              />
              <WorkflowEvidencePanels
                key={`${tenantId}:${current.value.id}:${current.value.currentVersion}`}
                api={api}
                csrfToken={csrfToken}
                resource={current.value}
                tenantId={tenantId}
              />
            </>
          ) : (
            <WorkflowEmpty kind={kind} />
          )}
        </div>
      </div>
    </section>
  );
}

function WorkflowInventory({
  canManage,
  inventory,
  kind,
  selectedId,
  onCreate,
  onLoadMore,
  onRefresh,
  onSelect,
}: {
  canManage: boolean;
  inventory: InventoryState;
  kind: WorkflowKind;
  selectedId: string | null;
  onCreate: () => void;
  onLoadMore: (cursor: string) => void;
  onRefresh: () => void;
  onSelect: (id: string) => void;
}): React.JSX.Element {
  return (
    <aside className="workflow-inventory" aria-label={`${kind} workflows`}>
      <header>
        <div>
          <p className="section-label">Published lineages</p>
          <h2>{kind === "alert" ? "Alert" : "Case"} catalog</h2>
        </div>
        <Button
          type="button"
          variant="ghost"
          size="icon"
          aria-label="Refresh workflow catalog"
          disabled={
            inventory.kind === "loading" ||
            (inventory.kind === "ready" && inventory.loadingMore)
          }
          onClick={onRefresh}
        >
          <RefreshCw aria-hidden="true" />
        </Button>
      </header>
      {canManage ? (
        <Button type="button" className="workflow-create" onClick={onCreate}>
          <Plus aria-hidden="true" /> New lineage
        </Button>
      ) : null}
      {inventory.kind === "loading" ? (
        <p role="status">Loading workflow catalog…</p>
      ) : inventory.kind === "error" ? (
        <WorkflowFailure message={inventory.message} />
      ) : inventory.items.length === 0 ? (
        <p>No workflow lineages are visible.</p>
      ) : (
        <div className="workflow-inventory__items">
          {inventory.items.map((workflow) => (
            <button
              key={workflow.id}
              type="button"
              aria-current={selectedId === workflow.id ? "true" : undefined}
              onClick={() => onSelect(workflow.id)}
            >
              <span>
                <strong>{workflow.displayName}</strong>
                <small>{workflow.key}</small>
              </span>
              <span>
                v{workflow.currentVersion}
                {workflow.isDefault ? <Star aria-label="Default" /> : null}
              </span>
            </button>
          ))}
        </div>
      )}
      {inventory.kind === "ready" && inventory.loadError ? (
        <WorkflowFailure message={inventory.loadError} />
      ) : null}
      {inventory.kind === "ready" && inventory.nextCursor ? (
        <Button
          type="button"
          variant="outline"
          disabled={inventory.loadingMore}
          onClick={() => onLoadMore(inventory.nextCursor!)}
        >
          {inventory.loadingMore ? "Loading more…" : "Load more workflows"}
        </Button>
      ) : null}
    </aside>
  );
}

function WorkflowEvidencePanels({
  api,
  csrfToken,
  resource,
  tenantId,
}: {
  api: WorkflowAdministrationApi;
  csrfToken: string;
  resource: ManagedWorkflow;
  tenantId: string;
}): React.JSX.Element {
  const [panel, setPanel] = useState<"history" | "simulator">("history");
  return (
    <section className="workflow-evidence" aria-label="Workflow evidence">
      <div role="tablist" aria-label="Workflow evidence panels">
        <button
          type="button"
          role="tab"
          aria-selected={panel === "history"}
          onClick={() => setPanel("history")}
        >
          <History aria-hidden="true" /> Publication history
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={panel === "simulator"}
          onClick={() => setPanel("simulator")}
        >
          <FlaskConical aria-hidden="true" /> Simulator
        </button>
      </div>
      {panel === "history" ? (
        <WorkflowHistory api={api} resource={resource} tenantId={tenantId} />
      ) : (
        <WorkflowSimulator
          api={api}
          csrfToken={csrfToken}
          resource={resource}
          tenantId={tenantId}
        />
      )}
    </section>
  );
}

function WorkflowHistory({
  api,
  resource,
  tenantId,
}: {
  api: WorkflowAdministrationApi;
  resource: ManagedWorkflow;
  tenantId: string;
}): React.JSX.Element {
  const [history, setHistory] = useState<
    | { kind: "error"; message: string }
    | { kind: "loading" }
    | {
        items: WorkflowVersion[];
        kind: "ready";
        loadError: string | null;
        loadingMore: boolean;
        nextVersion?: number;
      }
  >({ kind: "loading" });
  const generation = useRef(0);
  const requestController = useRef<AbortController | null>(null);
  useEffect(() => {
    const requestGeneration = ++generation.current;
    requestController.current?.abort();
    const controller = new AbortController();
    requestController.current = controller;
    setHistory({ kind: "loading" });
    void api
      .listVersions({
        limit: 100,
        signal: controller.signal,
        tenantId,
        workflowId: resource.id,
      })
      .then((page) => {
        if (
          controller.signal.aborted ||
          requestGeneration !== generation.current
        )
          return;
        setHistory({
          items: validateVersions(page.items, tenantId, resource),
          kind: "ready",
          loadError: null,
          loadingMore: false,
          ...(page.nextVersion === undefined
            ? {}
            : { nextVersion: page.nextVersion }),
        });
      })
      .catch((caught: unknown) => {
        if (
          !controller.signal.aborted &&
          requestGeneration === generation.current
        ) {
          setHistory({
            kind: "error",
            message: workflowErrorMessage(caught),
          });
        }
      });
    return () => {
      requestController.current?.abort();
      if (requestGeneration === generation.current) generation.current += 1;
    };
  }, [api, resource, tenantId]);

  async function loadMore(): Promise<void> {
    if (
      history.kind !== "ready" ||
      history.loadingMore ||
      history.nextVersion === undefined
    )
      return;
    const previous = history;
    const requestGeneration = ++generation.current;
    requestController.current?.abort();
    const controller = new AbortController();
    requestController.current = controller;
    setHistory({ ...previous, loadError: null, loadingMore: true });
    try {
      const page = await api.listVersions({
        afterVersion: previous.nextVersion,
        limit: 100,
        signal: controller.signal,
        tenantId,
        workflowId: resource.id,
      });
      if (controller.signal.aborted || requestGeneration !== generation.current)
        return;
      if (
        page.nextVersion === previous.nextVersion ||
        (page.nextVersion !== undefined && page.items.length === 0)
      ) {
        throw new WorkflowInputError(
          "The workflow history cursor did not make progress.",
        );
      }
      setHistory({
        items: validateVersions(
          [...previous.items, ...page.items],
          tenantId,
          resource,
        ),
        kind: "ready",
        loadError: null,
        loadingMore: false,
        ...(page.nextVersion === undefined
          ? {}
          : { nextVersion: page.nextVersion }),
      });
    } catch (caught: unknown) {
      if (
        !controller.signal.aborted &&
        requestGeneration === generation.current
      ) {
        setHistory({
          ...previous,
          loadError: workflowErrorMessage(caught),
          loadingMore: false,
        });
      }
    }
  }

  if (history.kind === "error") {
    return <WorkflowFailure message={history.message} />;
  }
  if (history.kind === "loading") {
    return <p role="status">Loading immutable history…</p>;
  }
  return (
    <div className="workflow-history">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Version</TableHead>
            <TableHead>Published</TableHead>
            <TableHead>Publisher</TableHead>
            <TableHead>Topology</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {history.items.map((version) => (
            <TableRow key={version.definition.version}>
              <TableCell>v{version.definition.version}</TableCell>
              <TableCell>{formatInstant(version.publishedAt)}</TableCell>
              <TableCell>{version.publisherDisplayName}</TableCell>
              <TableCell>
                {version.definition.states.length} states ·{" "}
                {version.definition.transitions.length} transitions
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      {history.loadError ? (
        <WorkflowFailure message={history.loadError} />
      ) : null}
      {history.nextVersion !== undefined ? (
        <Button
          type="button"
          variant="outline"
          disabled={history.loadingMore}
          onClick={() => void loadMore()}
        >
          {history.loadingMore ? "Loading older…" : "Load older publications"}
        </Button>
      ) : null}
    </div>
  );
}

interface SimulationDraft {
  commentPresent: boolean;
  factsJson: string;
  permissions: string;
  providedCustomFields: string;
  roles: string;
  state: string;
  version: string;
}

function WorkflowSimulator({
  api,
  csrfToken,
  resource,
  tenantId,
}: {
  api: WorkflowAdministrationApi;
  csrfToken: string;
  resource: ManagedWorkflow;
  tenantId: string;
}): React.JSX.Element {
  const [draft, setDraft] = useState<SimulationDraft>(() => ({
    commentPresent: false,
    factsJson: "[]",
    permissions: "",
    providedCustomFields: "",
    roles: "",
    state: resource.current.initialState,
    version: String(resource.currentVersion),
  }));
  const [result, setResult] = useState<WorkflowSimulationResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function simulate(): Promise<void> {
    setError(null);
    setBusy(true);
    try {
      const body = normalizeWorkflowSimulation(
        resource.kind,
        resource.current,
        {
          commentPresent: draft.commentPresent,
          facts: parseFacts(draft.factsJson),
          permissions: parsePermissions(draft.permissions, resource.kind),
          providedCustomFields: splitList(draft.providedCustomFields),
          roles: splitList(draft.roles),
          state: draft.state,
          version: parseSimulationVersion(draft.version),
        },
      );
      const next = await api.simulate({
        body,
        csrfToken,
        tenantId,
        workflowId: resource.id,
      });
      if (
        next.workflowId !== resource.id ||
        next.kind !== resource.kind ||
        (body.version !== 0 && next.version !== body.version) ||
        !next.explanatory
      ) {
        throw new WorkflowInputError(
          "The simulator returned a mismatched workflow projection.",
        );
      }
      setResult(next);
    } catch (caught: unknown) {
      setResult(null);
      setError(workflowErrorMessage(caught));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="workflow-simulator">
      <div className="workflow-simulator__form">
        <FormField htmlFor="workflow-simulation-version" label="Version">
          <Input
            id="workflow-simulation-version"
            inputMode="numeric"
            disabled={busy}
            value={draft.version}
            onChange={(event) =>
              setDraft({ ...draft, version: event.target.value })
            }
          />
        </FormField>
        <FormField htmlFor="workflow-simulation-state" label="Current state">
          <Input
            id="workflow-simulation-state"
            disabled={busy}
            value={draft.state}
            onChange={(event) =>
              setDraft({ ...draft, state: event.target.value })
            }
          />
        </FormField>
        <FormField htmlFor="workflow-simulation-roles" label="Roles">
          <Input
            id="workflow-simulation-roles"
            disabled={busy}
            placeholder="analyst, senior_analyst"
            value={draft.roles}
            onChange={(event) =>
              setDraft({ ...draft, roles: event.target.value })
            }
          />
        </FormField>
        <FormField
          htmlFor="workflow-simulation-permissions"
          label="Permissions"
        >
          <Input
            id="workflow-simulation-permissions"
            disabled={busy}
            placeholder={`${resource.kind}.update`}
            value={draft.permissions}
            onChange={(event) =>
              setDraft({ ...draft, permissions: event.target.value })
            }
          />
        </FormField>
        <FormField
          htmlFor="workflow-simulation-custom-fields"
          label="Provided custom fields"
        >
          <Input
            id="workflow-simulation-custom-fields"
            disabled={busy}
            placeholder="resolution, containment_status"
            value={draft.providedCustomFields}
            onChange={(event) =>
              setDraft({ ...draft, providedCustomFields: event.target.value })
            }
          />
        </FormField>
        <label className="workflow-simulator__check">
          <Checkbox
            checked={draft.commentPresent}
            disabled={busy}
            onCheckedChange={(value) =>
              setDraft({ ...draft, commentPresent: value === true })
            }
          />
          Required comment is present
        </label>
        <div className="workflow-simulator__wide">
          <FormField
            htmlFor="workflow-simulation-facts"
            label="Typed facts"
            hint='Strict JSON array, for example [{"field":"severity","value":{"type":"text","value":"high"}}].'
          >
            <Textarea
              id="workflow-simulation-facts"
              rows={5}
              disabled={busy}
              spellCheck={false}
              value={draft.factsJson}
              onChange={(event) =>
                setDraft({ ...draft, factsJson: event.target.value })
              }
            />
          </FormField>
        </div>
        <Button type="button" disabled={busy} onClick={() => void simulate()}>
          <FlaskConical aria-hidden="true" />
          {busy ? "Simulating…" : "Run bounded simulation"}
        </Button>
      </div>
      <div className="workflow-simulator__result" aria-live="polite">
        <p>
          Explanatory only. Simulation output never grants authority or mutates
          a ticket.
        </p>
        {error ? <WorkflowFailure message={error} /> : null}
        {!result && !error ? (
          <p>Run a scenario to inspect every transition gate.</p>
        ) : null}
        {result ? (
          <p>Evaluated immutable publication v{result.version}.</p>
        ) : null}
        {result?.transitions.length === 0 ? (
          <p>No outgoing transitions exist for this state.</p>
        ) : null}
        {result?.transitions.map((transition) => (
          <article key={transition.key}>
            <header>
              <strong>{transition.key}</strong>
              <Badge variant={transition.eligible ? "secondary" : "outline"}>
                {transition.eligible ? "eligible" : "blocked"}
              </Badge>
            </header>
            <p>
              {transition.from} → {transition.to}
            </p>
            <dl>
              {Object.entries(transition.gates).map(([gate, satisfied]) => (
                <div key={gate}>
                  <dt>{humanize(gate)}</dt>
                  <dd>{satisfied ? "pass" : "blocked"}</dd>
                </div>
              ))}
              <SimulationDetail
                label="Missing roles"
                values={transition.missingRoles}
              />
              <SimulationDetail
                label="Missing permissions"
                values={transition.missingPermissions}
              />
              <SimulationDetail
                label="Missing custom fields"
                values={transition.missingCustomFields}
              />
              <SimulationDetail label="Effects" values={transition.effects} />
            </dl>
          </article>
        ))}
      </div>
    </div>
  );
}

function SimulationDetail({
  label,
  values,
}: {
  label: string;
  values: readonly string[];
}): React.JSX.Element {
  return (
    <div>
      <dt>{label}</dt>
      <dd>{values.join(", ") || "None"}</dd>
    </div>
  );
}

function parseFacts(source: string): WorkflowSimulationFact[] {
  if (
    source.trim().length === 0 ||
    new TextEncoder().encode(source).byteLength > 128 * 1024
  ) {
    throw new WorkflowInputError("Simulation facts are empty or too large.");
  }
  let value: unknown;
  try {
    value = JSON.parse(source);
  } catch {
    throw new WorkflowInputError("Simulation facts must be valid JSON.");
  }
  if (!Array.isArray(value) || value.length > 256) {
    throw new WorkflowInputError("Simulation facts must be a bounded array.");
  }
  return value.map((item) => {
    if (!isRecord(item) || typeof item.field !== "string") {
      throw new WorkflowInputError("Simulation fact shape is unsupported.");
    }
    const keys = Object.keys(item);
    if (
      keys.some((key) => key !== "field" && key !== "value") ||
      keys.length !== ("value" in item ? 2 : 1)
    ) {
      throw new WorkflowInputError("Simulation fact shape is unsupported.");
    }
    return {
      field: item.field,
      ...(item.value === undefined
        ? {}
        : { value: parseConditionValue(item.value) }),
    };
  });
}

function parseConditionValue(value: unknown): WorkflowConditionValue {
  if (!isRecord(value) || Object.keys(value).length !== 2) {
    throw new WorkflowInputError("Simulation fact value is unsupported.");
  }
  if (value.type === "text" && typeof value.value === "string")
    return { type: "text", value: value.value };
  if (value.type === "number" && typeof value.value === "number")
    return { type: "number", value: value.value };
  if (value.type === "boolean" && typeof value.value === "boolean")
    return { type: "boolean", value: value.value };
  if (value.type === "instant" && typeof value.value === "string")
    return { type: "instant", value: value.value };
  throw new WorkflowInputError("Simulation fact value is unsupported.");
}

function validateInventory(
  items: ManagedWorkflow[],
  tenantId: string,
  kind: WorkflowKind,
): ManagedWorkflow[] {
  const ids = new Set<string>();
  let previousId = "";
  for (const item of items) {
    if (
      item.tenantId !== tenantId ||
      item.kind !== kind ||
      ids.has(item.id) ||
      item.id <= previousId ||
      item.current.id !== item.id ||
      item.current.kind !== item.kind ||
      item.current.version !== item.currentVersion
    ) {
      throw new WorkflowInputError(
        "The workflow catalog crossed its tenant or kind boundary.",
      );
    }
    ids.add(item.id);
    previousId = item.id;
  }
  return items;
}

function validateVersionedWorkflow(
  resource: VersionedWorkflow,
  tenantId: string,
  workflowId: string | undefined,
  kind: WorkflowKind,
): VersionedWorkflow {
  const etagPattern = /^"v([1-9]\d{0,9})-[A-Za-z0-9_-]{43}"$/u;
  const etagMatch = etagPattern.exec(resource.etag);
  const value = resource.value;
  if (
    !etagMatch ||
    Number(etagMatch[1]) !== value.revision ||
    value.tenantId !== tenantId ||
    value.kind !== kind ||
    (workflowId !== undefined && value.id !== workflowId) ||
    value.current.id !== value.id ||
    value.current.kind !== value.kind ||
    value.current.version !== value.currentVersion
  ) {
    throw new WorkflowInputError(
      "The workflow response crossed its resource boundary.",
    );
  }
  return resource;
}

function requireUnchangedPublication(
  previous: ManagedWorkflow,
  next: ManagedWorkflow,
): void {
  if (
    next.currentVersion !== previous.currentVersion ||
    next.current.id !== previous.current.id ||
    next.current.kind !== previous.current.kind ||
    next.current.version !== previous.current.version ||
    next.current.initialState !== previous.current.initialState ||
    JSON.stringify({
      states: next.current.states,
      transitions: next.current.transitions,
    }) !==
      JSON.stringify({
        states: previous.current.states,
        transitions: previous.current.transitions,
      })
  ) {
    throw new WorkflowInputError(
      "The catalog mutation unexpectedly changed an immutable publication.",
    );
  }
}

function requireNonRegressingReplayRefresh(
  replay: ManagedWorkflow,
  current: ManagedWorkflow,
): void {
  if (
    current.revision < replay.revision ||
    (current.revision === replay.revision &&
      JSON.stringify(current) !== JSON.stringify(replay))
  ) {
    throw new WorkflowInputError(
      "The current workflow revision regressed behind its replay snapshot.",
    );
  }
}

function validateVersions(
  items: WorkflowVersion[],
  tenantId: string,
  workflow: ManagedWorkflow,
): WorkflowVersion[] {
  if (items[0]?.definition.version !== workflow.currentVersion) {
    throw new WorkflowInputError(
      "The workflow history omitted its current immutable publication.",
    );
  }
  let previous = Number.POSITIVE_INFINITY;
  for (const item of items) {
    if (
      item.tenantId !== tenantId ||
      item.workflowId !== workflow.id ||
      item.definition.id !== workflow.id ||
      item.definition.kind !== workflow.kind ||
      item.definition.version >= previous ||
      item.definition.version > workflow.currentVersion
    ) {
      throw new WorkflowInputError(
        "The workflow history crossed its immutable lineage boundary.",
      );
    }
    previous = item.definition.version;
  }
  return items;
}

function WorkflowLoading(): React.JSX.Element {
  return <p role="status">Loading the selected workflow…</p>;
}

function WorkflowFailure({ message }: { message: string }): React.JSX.Element {
  return (
    <div className="workflow-failure" role="alert">
      <ShieldAlert aria-hidden="true" />
      <span>{message}</span>
    </div>
  );
}

function WorkflowEmpty({ kind }: { kind: WorkflowKind }): React.JSX.Element {
  return (
    <div className="workflow-empty">
      <GitBranch aria-hidden="true" />
      <h2>Select a {kind} workflow</h2>
      <p>
        Inspect its immutable publication history or create a new governed
        lineage if workflow.manage is available.
      </p>
    </div>
  );
}

function workflowErrorMessage(error: unknown): string {
  return error instanceof WorkflowInputError ||
    error instanceof WorkflowApiError
    ? error.message
    : "The workflow request could not be completed.";
}

function splitList(value: string): string[] {
  return value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function parseSimulationVersion(value: string): number {
  if (!/^(?:0|[1-9]\d*)$/u.test(value)) {
    throw new WorkflowInputError(
      "Simulation version must be zero or a positive version.",
    );
  }
  return Number(value);
}

function parsePermissions(
  value: string,
  kind: WorkflowKind,
): WorkflowPermission[] {
  const allowed: readonly WorkflowPermission[] =
    kind === "alert"
      ? [
          "alert.create",
          "alert.update",
          "alert.assign",
          "alert.claim",
          "alert.escalate",
          "alert.comment.public",
          "alert.comment.private",
        ]
      : [
          "case.create",
          "case.update",
          "case.claim",
          "case.transfer",
          "case.transition",
          "case.comment.public",
          "case.comment.private",
        ];
  const result: WorkflowPermission[] = [];
  for (const permission of splitList(value)) {
    const matched = allowed.find((candidate) => candidate === permission);
    if (!matched) {
      throw new WorkflowInputError(
        "Simulation permission is unsupported for this workflow kind.",
      );
    }
    result.push(matched);
  }
  return result;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function formatInstant(value: string): string {
  const parsed = Date.parse(value);
  return Number.isFinite(parsed)
    ? new Intl.DateTimeFormat(undefined, {
        dateStyle: "medium",
        timeStyle: "short",
      }).format(parsed)
    : "Invalid timestamp";
}

function humanize(value: string): string {
  return value
    .replaceAll(/([a-z])([A-Z])/gu, "$1 $2")
    .replaceAll("_", " ")
    .toLowerCase();
}
