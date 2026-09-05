import type {
  SavedTicketView,
  SavedTicketViewSpecInput,
} from "@periapsis/contracts";
import { Badge } from "@periapsis/ui/components/ui/badge";
import { Button } from "@periapsis/ui/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@periapsis/ui/components/ui/dialog";
import { Input } from "@periapsis/ui/components/ui/input";
import {
  Archive,
  Bookmark,
  CopyPlus,
  LoaderCircle,
  RefreshCw,
  RotateCcw,
  Save,
  ShieldAlert,
} from "lucide-react";
import { useEffect, useRef, useState, type FormEvent } from "react";

import {
  TicketingApiError,
  describeTicketingError,
  type SavedTicketViewMutationView,
  type TicketKind,
  type TicketingApi,
  type VersionedSavedTicketView,
} from "../lib/ticketing-api";
import { hasControlCharacters } from "../lib/text-validation";
import {
  acquireSavedViewAttempt,
  savedViewSelectionLabel,
  type SavedViewAttempt,
  type SavedViewURLSelection,
} from "./saved-view-model";
// oxlint-disable-next-line import/no-unassigned-import -- Vite extracts this module-owned stylesheet.
import "./saved-view-controls.css";

const maximumViewNameLength = 120;

type NameDialogMode = "create" | "save-as";
type LifecycleMode = "archive" | "restore";

export interface SavedViewControlsProps {
  api: TicketingApi;
  canPersist: boolean;
  csrfToken: string;
  currentSpec: SavedTicketViewSpecInput;
  inventoryError: unknown;
  inventoryLoading: boolean;
  inventoryLoadingMore?: boolean;
  inventoryHasMore?: boolean;
  kind: TicketKind;
  onForbidden?: () => void;
  onMutation: (
    result: SavedTicketViewMutationView,
    action: "archive" | "create" | "replace" | "restore",
  ) => void;
  onReload: () => void;
  onLoadMore?: () => void;
  onSelect: (viewId?: string) => void;
  onUnauthorized?: () => void;
  selected: VersionedSavedTicketView | undefined;
  selectedError: unknown;
  selectedLoading: boolean;
  selection: SavedViewURLSelection;
  tenantId: string;
  views: readonly SavedTicketView[];
}

export function SavedViewControls({
  api,
  canPersist,
  csrfToken,
  currentSpec,
  inventoryError,
  inventoryHasMore = false,
  inventoryLoading,
  inventoryLoadingMore = false,
  kind,
  onForbidden,
  onMutation,
  onLoadMore,
  onReload,
  onSelect,
  onUnauthorized,
  selected,
  selectedError,
  selectedLoading,
  selection,
  tenantId,
  views,
}: SavedViewControlsProps): React.JSX.Element {
  const attemptRef = useRef<SavedViewAttempt | undefined>(undefined);
  const [nameDialog, setNameDialog] = useState<NameDialogMode>();
  const [lifecycleDialog, setLifecycleDialog] = useState<LifecycleMode>();
  const [name, setName] = useState("");
  const [mutationError, setMutationError] = useState<unknown>();
  const [pending, setPending] = useState(false);
  const selectedValue = selection.kind === "selected" ? selection.viewId : "";
  const selectableViews =
    selected && !views.some((view) => view.id === selected.value.id)
      ? [...views, selected.value]
      : views;
  const activeViews = selectableViews.filter(
    (view) => view.status === "active",
  );
  const archivedViews = selectableViews.filter(
    (view) => view.status === "archived",
  );
  const integrityReady = canPersist && csrfToken.trim() !== "" && !pending;

  useEffect(() => {
    attemptRef.current = undefined;
    setMutationError(undefined);
    setNameDialog(undefined);
    setLifecycleDialog(undefined);
  }, [kind, selectedValue, tenantId]);

  function openNameDialog(mode: NameDialogMode): void {
    setMutationError(undefined);
    setName(
      mode === "save-as" && selected ? `${selected.value.name} copy` : "",
    );
    setNameDialog(mode);
  }

  async function submitName(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (!integrityReady) return;
    const canonicalName = name.trim();
    if (
      canonicalName.length === 0 ||
      Array.from(canonicalName).length > maximumViewNameLength ||
      new TextEncoder().encode(canonicalName).byteLength >
        maximumViewNameLength ||
      hasControlCharacters(canonicalName)
    ) {
      setMutationError(
        new TypeError("Enter a view name using at most 120 UTF-8 bytes."),
      );
      return;
    }
    const body = { kind, name: canonicalName, spec: currentSpec } as const;
    const intent = nameDialog === "save-as" ? "save-as" : "create";
    await runMutation(intent, body, async (idempotencyKey) =>
      api.createSavedTicketView({
        body,
        csrfToken,
        idempotencyKey,
        tenantId,
      }),
    );
  }

  async function updateSelected(): Promise<void> {
    if (!integrityReady || !selected || selected.value.status !== "active")
      return;
    const body = {
      kind,
      expectedRevision: selected.value.revision,
      name: selected.value.name,
      spec: currentSpec,
    } as const;
    await runMutation(
      "replace",
      { body, etag: selected.etag, viewId: selected.value.id },
      async (idempotencyKey) =>
        api.replaceSavedTicketView({
          body,
          csrfToken,
          etag: selected.etag,
          idempotencyKey,
          tenantId,
          viewId: selected.value.id,
        }),
    );
  }

  async function changeLifecycle(mode: LifecycleMode): Promise<void> {
    if (!integrityReady || !selected) return;
    const body = { kind, expectedRevision: selected.value.revision } as const;
    await runMutation(
      mode,
      { body, etag: selected.etag, viewId: selected.value.id },
      async (idempotencyKey) =>
        mode === "archive"
          ? api.archiveSavedTicketView({
              body,
              csrfToken,
              etag: selected.etag,
              idempotencyKey,
              tenantId,
              viewId: selected.value.id,
            })
          : api.restoreSavedTicketView({
              body,
              csrfToken,
              etag: selected.etag,
              idempotencyKey,
              tenantId,
              viewId: selected.value.id,
            }),
    );
  }

  async function runMutation(
    intent: string,
    payload: unknown,
    execute: (idempotencyKey: string) => Promise<SavedTicketViewMutationView>,
  ): Promise<void> {
    setMutationError(undefined);
    let attempt: SavedViewAttempt;
    try {
      attempt = acquireSavedViewAttempt(attemptRef.current, intent, payload);
      attemptRef.current = attempt;
    } catch (error) {
      setMutationError(error);
      return;
    }
    setPending(true);
    try {
      const result = await execute(attempt.key);
      attemptRef.current = undefined;
      setNameDialog(undefined);
      setLifecycleDialog(undefined);
      onMutation(result, mutationAction(intent));
    } catch (error) {
      setMutationError(error);
      if (error instanceof TicketingApiError) {
        if (error.status === 401) onUnauthorized?.();
        if (error.status === 403) onForbidden?.();
      }
    } finally {
      setPending(false);
    }
  }

  return (
    <section className="saved-view-bar" aria-labelledby="saved-view-title">
      <div className="saved-view-bar__identity">
        <span className="saved-view-bar__icon" aria-hidden="true">
          <Bookmark />
        </span>
        <div>
          <p className="section-label">Private workspace</p>
          <h2 id="saved-view-title">Ticket view</h2>
        </div>
      </div>

      <label className="saved-view-selector">
        <span>Selected view</span>
        <select
          aria-invalid={selection.kind === "invalid" || undefined}
          disabled={inventoryLoading || !canPersist}
          value={selection.kind === "invalid" ? "__invalid" : selectedValue}
          onChange={(event) =>
            onSelect(event.target.value === "" ? undefined : event.target.value)
          }
        >
          {selection.kind === "invalid" ? (
            <option value="__invalid">Invalid view link</option>
          ) : null}
          <option value="">Unsaved current view</option>
          {activeViews.length > 0 ? (
            <optgroup label="Active views">
              {activeViews.map((view) => (
                <option key={view.id} value={view.id}>
                  {savedViewSelectionLabel(view)}
                </option>
              ))}
            </optgroup>
          ) : null}
          {archivedViews.length > 0 ? (
            <optgroup label="Archived views">
              {archivedViews.map((view) => (
                <option key={view.id} value={view.id}>
                  {savedViewSelectionLabel(view)}
                </option>
              ))}
            </optgroup>
          ) : null}
        </select>
      </label>

      <div className="saved-view-bar__actions">
        {inventoryHasMore ? (
          <Button
            type="button"
            size="sm"
            variant="ghost"
            disabled={inventoryLoadingMore}
            onClick={onLoadMore}
          >
            {inventoryLoadingMore ? (
              <LoaderCircle className="is-spinning" aria-hidden="true" />
            ) : null}
            Load more views
          </Button>
        ) : null}
        {selection.kind === "invalid" ? (
          <Button
            type="button"
            size="sm"
            variant="outline"
            onClick={() => onSelect()}
          >
            <RotateCcw aria-hidden="true" /> Clear invalid link
          </Button>
        ) : null}
        {selection.kind === "none" ? (
          <Button
            type="button"
            size="sm"
            disabled={!integrityReady}
            onClick={() => openNameDialog("create")}
          >
            <Save aria-hidden="true" /> Save current
          </Button>
        ) : null}
        {selected ? (
          <>
            <Button
              type="button"
              size="sm"
              variant="outline"
              disabled={!integrityReady}
              onClick={() => openNameDialog("save-as")}
            >
              <CopyPlus aria-hidden="true" /> Save as
            </Button>
            {selected.value.status === "active" ? (
              <>
                <Button
                  type="button"
                  size="sm"
                  disabled={!integrityReady}
                  onClick={() => void updateSelected()}
                >
                  <Save aria-hidden="true" /> Update
                </Button>
                <Button
                  type="button"
                  size="sm"
                  variant="ghost"
                  disabled={!integrityReady}
                  onClick={() => setLifecycleDialog("archive")}
                >
                  <Archive aria-hidden="true" /> Archive
                </Button>
              </>
            ) : (
              <Button
                type="button"
                size="sm"
                disabled={!integrityReady}
                onClick={() => setLifecycleDialog("restore")}
              >
                <RotateCcw aria-hidden="true" /> Restore
              </Button>
            )}
          </>
        ) : null}
      </div>

      <SavedViewStatus
        inventoryError={inventoryError}
        inventoryLoading={inventoryLoading}
        mutationError={mutationError}
        onReload={() => {
          setMutationError(undefined);
          onReload();
        }}
        pending={pending}
        selected={selected}
        selectedError={selectedError}
        selectedLoading={selectedLoading}
        selection={selection}
      />

      {selected ? <SavedViewDefinitionSummary view={selected.value} /> : null}

      <Dialog
        open={nameDialog !== undefined}
        onOpenChange={(open) => !open && setNameDialog(undefined)}
      >
        <DialogContent className="saved-view-dialog">
          <form onSubmit={(event) => void submitName(event)}>
            <DialogHeader>
              <DialogTitle>
                {nameDialog === "save-as"
                  ? "Save a private copy"
                  : "Save current view"}
              </DialogTitle>
              <DialogDescription>
                Filters, sort, ordered columns, widths, visibility, and pins are
                stored for this exact membership only.
              </DialogDescription>
            </DialogHeader>
            <label className="saved-view-dialog__field">
              <span>View name</span>
              <Input
                autoFocus
                maxLength={maximumViewNameLength}
                required
                value={name}
                onChange={(event) => setName(event.target.value)}
              />
            </label>
            <DialogFooter>
              <Button
                type="button"
                variant="ghost"
                onClick={() => setNameDialog(undefined)}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={!integrityReady}>
                {pending ? (
                  <LoaderCircle className="is-spinning" aria-hidden="true" />
                ) : (
                  <Save aria-hidden="true" />
                )}
                Save view
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      <Dialog
        open={lifecycleDialog !== undefined}
        onOpenChange={(open) => !open && setLifecycleDialog(undefined)}
      >
        <DialogContent className="saved-view-dialog">
          <DialogHeader>
            <DialogTitle>
              {lifecycleDialog === "archive"
                ? "Archive this view?"
                : "Restore this view?"}
            </DialogTitle>
            <DialogDescription>
              {lifecycleDialog === "archive"
                ? "The URL will stop executing this view, but its forensic record remains available in the selector."
                : "Every custom-field and SLA definition pin will be checked again before this view can execute."}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button
              type="button"
              variant="ghost"
              onClick={() => setLifecycleDialog(undefined)}
            >
              Cancel
            </Button>
            <Button
              type="button"
              disabled={!integrityReady || lifecycleDialog === undefined}
              onClick={() =>
                lifecycleDialog && void changeLifecycle(lifecycleDialog)
              }
            >
              {pending ? (
                <LoaderCircle className="is-spinning" aria-hidden="true" />
              ) : null}
              {lifecycleDialog === "archive" ? "Archive view" : "Restore view"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </section>
  );
}

function SavedViewStatus({
  inventoryError,
  inventoryLoading,
  mutationError,
  onReload,
  pending,
  selected,
  selectedError,
  selectedLoading,
  selection,
}: Pick<
  SavedViewControlsProps,
  | "inventoryError"
  | "inventoryLoading"
  | "onReload"
  | "selected"
  | "selectedError"
  | "selectedLoading"
  | "selection"
> & { mutationError?: unknown; pending: boolean }): React.JSX.Element | null {
  const error = mutationError ?? selectedError ?? inventoryError;
  if (pending || inventoryLoading || selectedLoading) {
    return (
      <p className="saved-view-status" role="status">
        <LoaderCircle className="is-spinning" aria-hidden="true" />
        {pending ? "Saving private view…" : "Loading private views…"}
      </p>
    );
  }
  if (selection.kind === "invalid") {
    return (
      <p className="saved-view-status saved-view-status--warning" role="alert">
        <ShieldAlert aria-hidden="true" /> This URL does not contain one
        canonical saved-view identifier. No view was executed.
      </p>
    );
  }
  if (error) {
    const conflict =
      error instanceof TicketingApiError &&
      (error.status === 409 || error.status === 412);
    return (
      <div className="saved-view-status saved-view-status--error" role="alert">
        <ShieldAlert aria-hidden="true" />
        <span>
          {error instanceof Error && !(error instanceof TicketingApiError)
            ? error.message
            : describeTicketingError(
                error,
                "Private saved views are unavailable. The unsaved queue remains usable.",
              )}
          {conflict
            ? " Reload the current version and review before retrying."
            : ""}
        </span>
        <Button type="button" size="sm" variant="ghost" onClick={onReload}>
          <RefreshCw aria-hidden="true" /> Reload and review
        </Button>
      </div>
    );
  }
  if (selected) {
    return (
      <p className="saved-view-status">
        <Badge variant="outline">Revision {selected.value.revision}</Badge>
        {selected.value.status === "archived"
          ? "Archived views cannot execute until their pinned definitions are revalidated."
          : "The backend proved this exact view revision for every returned page."}
      </p>
    );
  }
  return null;
}

function SavedViewDefinitionSummary({
  view,
}: {
  view: SavedTicketView;
}): React.JSX.Element {
  const dynamicColumns = view.spec.columns.filter(
    (column) => column.source !== "core",
  );
  return (
    <details className="saved-view-definition">
      <summary>View definition</summary>
      <dl>
        <div>
          <dt>Queue</dt>
          <dd>{view.spec.filters.queue.replaceAll("_", " ")}</dd>
        </div>
        <div>
          <dt>Custom filters</dt>
          <dd>{view.spec.filters.custom.length}</dd>
        </div>
        <div>
          <dt>Dynamic columns</dt>
          <dd>{dynamicColumns.length}</dd>
        </div>
        <div>
          <dt>Sort</dt>
          <dd>
            {view.spec.sort.source === "core"
              ? view.spec.sort.coreKey
              : view.spec.sort.definition?.key}
          </dd>
        </div>
      </dl>
      {view.spec.filters.custom.length > 0 ? (
        <ul aria-label="Pinned custom filters">
          {view.spec.filters.custom.map((filter) => (
            <li key={filter.definition.id}>
              <span>{filter.definition.key.replaceAll("_", " ")}</span>
              <Badge variant="outline">v{filter.definition.version}</Badge>
            </li>
          ))}
        </ul>
      ) : null}
    </details>
  );
}

function mutationAction(
  intent: string,
): "archive" | "create" | "replace" | "restore" {
  switch (intent) {
    case "archive":
      return "archive";
    case "replace":
      return "replace";
    case "restore":
      return "restore";
    default:
      return "create";
  }
}
