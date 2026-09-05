import { Badge } from "@periapsis/ui/components/ui/badge";
import { Button } from "@periapsis/ui/components/ui/button";
import { Checkbox } from "@periapsis/ui/components/ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@periapsis/ui/components/ui/dialog";
import { Input } from "@periapsis/ui/components/ui/input";
import { Label } from "@periapsis/ui/components/ui/label";
import { Textarea } from "@periapsis/ui/components/ui/textarea";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Archive,
  Braces,
  ChevronRight,
  CirclePlus,
  DatabaseZap,
  LoaderCircle,
  Search,
  ShieldX,
} from "lucide-react";
import { useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import type { RouteObject } from "react-router";

import { useSession } from "../auth/session-context";
import { useTenantAuthority } from "../auth/tenant-authority-context";
import { FocusedError } from "../components/focused-error";
import {
  idempotencyKeyForPayload,
  type IdempotencyReference,
} from "../lib/payload-idempotency";
import { generateUuidV7 } from "../lib/uuid-v7";
import {
  CustomFieldApiError,
  customFieldAdministrationApi,
  listAllCustomFieldDefinitions,
  type CustomFieldAdministrationApi,
} from "./custom-field-api";
import {
  definitionSpecFromDraft,
  draftFromDefinition,
  emptyDefinitionDraft,
  humanizeDataType,
  isSelectType,
  supportsNumericConstraints,
  supportsSearch,
  supportsSort,
  supportsTextConstraints,
  type CustomFieldDefinitionDraft,
} from "./definition-editor-model";
import {
  customFieldAdministrationRouteDescriptor,
  customFieldDataTypes,
  type CustomFieldDefinitionView,
  type CustomFieldObjectType,
} from "./model";
// oxlint-disable-next-line import/no-unassigned-import -- Vite extracts this route-owned stylesheet.
import "./custom-field-administration-page.css";

interface CustomFieldAdministrationPageProps {
  api?: CustomFieldAdministrationApi;
}

interface EditorState {
  current?: CustomFieldDefinitionView;
  definitionId: string;
  draft: CustomFieldDefinitionDraft;
  etag?: string;
}

export function TenantCustomFieldAdministrationPage({
  api = customFieldAdministrationApi,
}: CustomFieldAdministrationPageProps = {}): React.JSX.Element {
  const { session } = useSession();
  const authority = useTenantAuthority();
  const queryClient = useQueryClient();
  const tenantId = session.activeTenantId ?? "";
  const [objectType, setObjectType] = useState<CustomFieldObjectType>("alert");
  const [showArchived, setShowArchived] = useState(false);
  const [search, setSearch] = useState("");
  const [editor, setEditor] = useState<EditorState | null>(null);
  const [editorErrors, setEditorErrors] = useState<readonly string[]>([]);
  const [editorProblem, setEditorProblem] = useState<string | null>(null);
  const [archiveReason, setArchiveReason] = useState("");
  const [saving, setSaving] = useState(false);
  const [loadingDefinitionId, setLoadingDefinitionId] = useState<string | null>(
    null,
  );
  const saveAttempt = useRef<IdempotencyReference["current"]>(null);
  const archiveAttempt = useRef<IdempotencyReference["current"]>(null);
  const editLoad = useRef<AbortController | null>(null);
  const activeMutation = useRef<object | null>(null);
  const ready = Boolean(tenantId) && authority.status === "ready";
  const canRead =
    ready && authority.hasPermission("custom_field.read", "tenant");
  const canManage =
    ready && authority.hasPermission("custom_field.manage", "tenant");
  const authorizationKey = `${session.id}:${tenantId}:${objectType}:${canRead}:${canManage}`;
  const authorizationContext = useRef({ key: authorizationKey, token: {} });
  if (authorizationContext.current.key !== authorizationKey) {
    authorizationContext.current = { key: authorizationKey, token: {} };
  }
  const query = useQuery({
    enabled: canRead,
    gcTime: 0,
    queryKey: ["custom-field-administration", tenantId, objectType],
    queryFn: ({ signal }) =>
      listAllCustomFieldDefinitions(api, {
        includeArchived: true,
        objectType,
        signal,
        tenantId,
      }),
  });
  const definitions = useMemo(() => {
    const needle = search.trim().toLocaleLowerCase();
    return (query.data ?? []).filter(
      (definition) =>
        (showArchived || !definition.archived) &&
        (!needle ||
          definition.key.toLocaleLowerCase().includes(needle) ||
          definition.label.toLocaleLowerCase().includes(needle)),
    );
  }, [query.data, search, showArchived]);

  useEffect(() => {
    editLoad.current?.abort();
    editLoad.current = null;
    activeMutation.current = null;
    setEditor(null);
    setEditorErrors([]);
    setEditorProblem(null);
    setArchiveReason("");
    setLoadingDefinitionId(null);
    setSaving(false);
    saveAttempt.current = null;
    archiveAttempt.current = null;
  }, [objectType, tenantId]);

  useEffect(() => {
    if (!canManage) {
      editLoad.current?.abort();
      editLoad.current = null;
      activeMutation.current = null;
      setEditor(null);
      setLoadingDefinitionId(null);
      setSaving(false);
    }
  }, [canManage]);

  useEffect(() => {
    if (canRead) return;
    const filters = {
      exact: true,
      queryKey: ["custom-field-administration", tenantId, objectType],
    } as const;
    void queryClient.cancelQueries(filters);
    queryClient.removeQueries(filters);
  }, [canRead, objectType, queryClient, tenantId]);

  useEffect(
    () => () => {
      editLoad.current?.abort();
      activeMutation.current = null;
    },
    [],
  );

  if (tenantId && authority.status === "loading") {
    return <CustomFieldBoundary loading />;
  }
  if (!canRead) return <CustomFieldBoundary />;

  function beginCreate(): void {
    if (!canManage) return;
    editLoad.current?.abort();
    editLoad.current = null;
    setLoadingDefinitionId(null);
    setEditor({
      definitionId: generateUuidV7(),
      draft: emptyDefinitionDraft(objectType),
    });
    resetEditorFeedback();
  }

  async function beginEdit(
    definition: CustomFieldDefinitionView,
  ): Promise<void> {
    if (!canManage || definition.archived) return;
    editLoad.current?.abort();
    const controller = new AbortController();
    editLoad.current = controller;
    const requestedAuthorization = authorizationContext.current.token;
    setLoadingDefinitionId(definition.id);
    setEditorProblem(null);
    try {
      const current = await api.get({
        definitionId: definition.id,
        objectType,
        signal: controller.signal,
        tenantId,
      });
      if (
        controller.signal.aborted ||
        editLoad.current !== controller ||
        authorizationContext.current.token !== requestedAuthorization
      ) {
        return;
      }
      setEditor({
        current: current.value,
        definitionId: current.value.id,
        draft: draftFromDefinition(current.value),
        etag: current.etag,
      });
      resetEditorFeedback();
    } catch (error) {
      if (
        !controller.signal.aborted &&
        editLoad.current === controller &&
        authorizationContext.current.token === requestedAuthorization
      ) {
        setEditorProblem(describeCustomFieldError(error));
      }
    } finally {
      if (editLoad.current === controller) {
        editLoad.current = null;
        setLoadingDefinitionId(null);
      }
    }
  }

  async function saveDefinition(
    event: FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault();
    if (!editor || !canManage) return;
    const normalized = definitionSpecFromDraft(editor.draft, editor.current);
    setEditorErrors(normalized.errors);
    if (!normalized.spec) return;
    if (editor.current && !editor.etag) {
      setEditorProblem(
        "The current strong ETag is unavailable. Reload the definition before saving.",
      );
      return;
    }
    const payload = {
      action: editor.current ? "replace" : "create",
      definition: normalized.spec,
      definitionId: editor.definitionId,
      expectedVersion: editor.current?.schemaVersion,
      tenantId,
    };
    const idempotencyKey = idempotencyKeyForPayload(saveAttempt, payload);
    const mutation = {};
    activeMutation.current = mutation;
    const requestedAuthorization = authorizationContext.current.token;
    setSaving(true);
    setEditorProblem(null);
    try {
      if (editor.current) {
        await api.replace({
          csrfToken: session.csrfToken,
          definition: normalized.spec,
          definitionId: editor.definitionId,
          etag: editor.etag!,
          expectedVersion: editor.current.schemaVersion,
          idempotencyKey,
          tenantId,
        });
      } else {
        await api.create({
          csrfToken: session.csrfToken,
          definition: normalized.spec,
          definitionId: editor.definitionId,
          idempotencyKey,
          tenantId,
        });
      }
      if (
        activeMutation.current !== mutation ||
        authorizationContext.current.token !== requestedAuthorization
      ) {
        return;
      }
      saveAttempt.current = null;
      setEditor(null);
      await invalidateCatalog(queryClient, tenantId);
    } catch (error) {
      if (
        activeMutation.current === mutation &&
        authorizationContext.current.token === requestedAuthorization
      ) {
        setEditorProblem(describeCustomFieldError(error));
      }
    } finally {
      if (activeMutation.current === mutation) {
        activeMutation.current = null;
        setSaving(false);
      }
    }
  }

  async function archiveDefinition(): Promise<void> {
    if (!editor?.current || !editor.etag || !canManage) return;
    const reason = archiveReason.trim();
    if (!reason) {
      setEditorErrors(["Enter a reason before archiving this definition."]);
      return;
    }
    const payload = {
      action: "archive",
      definitionId: editor.definitionId,
      expectedVersion: editor.current.schemaVersion,
      objectType: editor.current.objectType,
      reason,
      tenantId,
    };
    const idempotencyKey = idempotencyKeyForPayload(archiveAttempt, payload);
    const mutation = {};
    activeMutation.current = mutation;
    const requestedAuthorization = authorizationContext.current.token;
    setSaving(true);
    setEditorProblem(null);
    try {
      await api.archive({
        csrfToken: session.csrfToken,
        definitionId: editor.definitionId,
        etag: editor.etag,
        expectedVersion: editor.current.schemaVersion,
        idempotencyKey,
        objectType: editor.current.objectType,
        reason,
        tenantId,
      });
      if (
        activeMutation.current !== mutation ||
        authorizationContext.current.token !== requestedAuthorization
      ) {
        return;
      }
      archiveAttempt.current = null;
      setEditor(null);
      await invalidateCatalog(queryClient, tenantId);
    } catch (error) {
      if (
        activeMutation.current === mutation &&
        authorizationContext.current.token === requestedAuthorization
      ) {
        setEditorProblem(describeCustomFieldError(error));
      }
    } finally {
      if (activeMutation.current === mutation) {
        activeMutation.current = null;
        setSaving(false);
      }
    }
  }

  function resetEditorFeedback(): void {
    setEditorErrors([]);
    setEditorProblem(null);
    setArchiveReason("");
    saveAttempt.current = null;
    archiveAttempt.current = null;
  }

  return (
    <div className="content custom-field-admin">
      <header className="custom-field-admin__hero">
        <div>
          <p className="section-label">Tenant schema studio</p>
          <h1>Custom fields with durable meaning.</h1>
          <p>
            Define typed Alert and Case data once. Visibility, edit policy,
            placement, filtering, sorting, and export behavior travel together
            as an immutable revision.
          </p>
        </div>
        {canManage ? (
          <Button type="button" onClick={beginCreate}>
            <CirclePlus aria-hidden="true" /> New {objectType} field
          </Button>
        ) : (
          <Badge variant="outline">Read only</Badge>
        )}
      </header>

      <section
        className="custom-field-admin__control-deck"
        aria-label="Catalog filters"
      >
        <div
          className="custom-field-admin__kind-tabs"
          role="group"
          aria-label="Object type"
        >
          {(["alert", "case"] as const).map((kind) => (
            <button
              aria-pressed={objectType === kind}
              key={kind}
              onClick={() => setObjectType(kind)}
              type="button"
            >
              {kind === "alert" ? "Alert schema" : "Case schema"}
            </button>
          ))}
        </div>
        <label className="custom-field-admin__search">
          <Search aria-hidden="true" />
          <span className="sr-only">Search custom fields</span>
          <Input
            placeholder="Search key or label"
            value={search}
            onChange={(event) => setSearch(event.currentTarget.value)}
          />
        </label>
        <label className="custom-field-admin__archived-toggle">
          <Checkbox
            checked={showArchived}
            onCheckedChange={(checked) => setShowArchived(checked === true)}
          />
          Show archived
        </label>
      </section>

      {editorProblem && !editor ? (
        <FocusedError title="Definition unavailable" message={editorProblem} />
      ) : null}
      {query.isPending ? <CatalogLoading /> : null}
      {query.isError ? (
        <div className="custom-field-admin__query-error">
          <FocusedError
            title="Custom-field catalog unavailable"
            message={describeCustomFieldError(query.error)}
          />
          <Button variant="outline" onClick={() => void query.refetch()}>
            Retry catalog
          </Button>
        </div>
      ) : null}
      {!query.isPending && !query.isError && definitions.length === 0 ? (
        <section className="custom-field-admin__empty">
          <DatabaseZap aria-hidden="true" />
          <h2>No matching {objectType} fields.</h2>
          <p>
            {showArchived || search
              ? "Change the filters to reveal another schema revision."
              : "Create the first typed field for this tenant when the workflow needs it."}
          </p>
        </section>
      ) : null}
      {definitions.length > 0 ? (
        <ul
          className="custom-field-admin__catalog"
          aria-label={`${objectType} custom fields`}
        >
          {definitions.map((definition) => (
            <DefinitionCard
              canManage={canManage}
              definition={definition}
              key={definition.id}
              loading={loadingDefinitionId === definition.id}
              onEdit={() => void beginEdit(definition)}
            />
          ))}
        </ul>
      ) : null}

      <Dialog
        open={editor !== null}
        onOpenChange={(open) => {
          if (!open && !saving) setEditor(null);
        }}
      >
        {editor ? (
          <DefinitionEditor
            archiveReason={archiveReason}
            editor={editor}
            errors={editorErrors}
            problem={editorProblem}
            saving={saving}
            onArchive={() => void archiveDefinition()}
            onArchiveReason={setArchiveReason}
            onCancel={() => setEditor(null)}
            onChange={(draft) => {
              setEditor((current) =>
                current ? { ...current, draft } : current,
              );
              setEditorErrors([]);
              setEditorProblem(null);
            }}
            onSubmit={(event) => void saveDefinition(event)}
          />
        ) : null}
      </Dialog>
    </div>
  );
}

function DefinitionCard({
  canManage,
  definition,
  loading,
  onEdit,
}: {
  canManage: boolean;
  definition: CustomFieldDefinitionView;
  loading: boolean;
  onEdit: () => void;
}): React.JSX.Element {
  return (
    <li>
      <article
        className="custom-field-card"
        data-archived={definition.archived || undefined}
      >
        <header>
          <span className="custom-field-card__glyph" aria-hidden="true">
            <Braces />
          </span>
          <div>
            <p>{definition.key}</p>
            <h2>{definition.label}</h2>
          </div>
          <Badge variant={definition.archived ? "outline" : "secondary"}>
            {definition.archived ? "Archived" : `v${definition.schemaVersion}`}
          </Badge>
        </header>
        <p className="custom-field-card__description">
          {definition.description || "No operator description."}
        </p>
        <div className="custom-field-card__facts">
          <span>{humanizeDataType(definition.dataType)}</span>
          <span>{definition.required ? "Required on create" : "Optional"}</span>
          <span>
            {definition.visibility.customer
              ? "Customer + operator"
              : "Operator only"}
          </span>
        </div>
        <footer>
          <span>
            {[
              definition.searchable && "search",
              definition.filterable && "filter",
              definition.sortable && "sort",
            ]
              .filter(Boolean)
              .join(" · ") || "detail only"}
          </span>
          {canManage && !definition.archived ? (
            <Button
              type="button"
              size="sm"
              variant="ghost"
              onClick={onEdit}
              disabled={loading}
            >
              {loading ? (
                <LoaderCircle className="is-spinning" aria-hidden="true" />
              ) : null}
              Edit <ChevronRight aria-hidden="true" />
            </Button>
          ) : null}
        </footer>
      </article>
    </li>
  );
}

function DefinitionEditor({
  archiveReason,
  editor,
  errors,
  onArchive,
  onArchiveReason,
  onCancel,
  onChange,
  onSubmit,
  problem,
  saving,
}: {
  archiveReason: string;
  editor: EditorState;
  errors: readonly string[];
  onArchive: () => void;
  onArchiveReason: (value: string) => void;
  onCancel: () => void;
  onChange: (draft: CustomFieldDefinitionDraft) => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
  problem: string | null;
  saving: boolean;
}): React.JSX.Element {
  const { draft, current } = editor;
  const update = <Key extends keyof CustomFieldDefinitionDraft>(
    key: Key,
    value: CustomFieldDefinitionDraft[Key],
  ) => onChange({ ...draft, [key]: value });
  return (
    <DialogContent className="custom-field-editor">
      <DialogHeader>
        <p className="section-label">
          {current ? `Revision ${current.schemaVersion}` : "New lineage"}
        </p>
        <DialogTitle>
          {current ? `Edit ${current.label}` : "Create a custom field"}
        </DialogTitle>
        <DialogDescription>
          The backend revalidates every value and commits the revision, audit
          event, and outbox effect atomically.
        </DialogDescription>
      </DialogHeader>
      <form onSubmit={onSubmit} className="custom-field-editor__form">
        {errors.length > 0 ? (
          <div className="custom-field-editor__errors" role="alert">
            <strong>Review this definition</strong>
            <ul>
              {errors.map((error) => (
                <li key={error}>{error}</li>
              ))}
            </ul>
          </div>
        ) : null}
        {problem ? (
          <FocusedError title="Definition not saved" message={problem} />
        ) : null}
        <div className="custom-field-editor__identity">
          <EditorTextField
            label="Key"
            value={draft.key}
            disabled={Boolean(current)}
            onChange={(value) => update("key", value)}
          />
          <EditorTextField
            label="Label"
            value={draft.label}
            maxLength={256}
            onChange={(value) => update("label", value)}
          />
          <label>
            <span>Data type</span>
            <select
              value={draft.dataType}
              disabled={Boolean(current)}
              onChange={(event) =>
                update("dataType", parseDataType(event.currentTarget.value))
              }
            >
              {customFieldDataTypes.map((dataType) => (
                <option key={dataType} value={dataType}>
                  {humanizeDataType(dataType)}
                </option>
              ))}
            </select>
          </label>
        </div>
        <label>
          <span>Description</span>
          <Textarea
            rows={3}
            maxLength={8192}
            value={draft.description}
            onChange={(event) =>
              update("description", event.currentTarget.value)
            }
          />
        </label>

        <EditorGroup legend="Value policy">
          <EditorToggle
            label="Required on create"
            checked={draft.required}
            onChange={(value) => update("required", value)}
          />
          <EditorToggle
            label="Explicit null allowed"
            checked={draft.nullable}
            onChange={(value) => update("nullable", value)}
          />
          <EditorTextField
            label="Required transition keys"
            hint="Comma-separated"
            value={draft.requiredOnTransitions}
            onChange={(value) => update("requiredOnTransitions", value)}
          />
        </EditorGroup>

        {supportsTextConstraints(draft.dataType) ? (
          <EditorGroup legend="Text constraints">
            <EditorTextField
              label="Minimum length"
              inputMode="numeric"
              value={draft.minimumLength}
              onChange={(value) => update("minimumLength", value)}
            />
            <EditorTextField
              label="Maximum length"
              inputMode="numeric"
              value={draft.maximumLength}
              onChange={(value) => update("maximumLength", value)}
            />
            <EditorTextField
              label="Regular expression"
              value={draft.pattern}
              onChange={(value) => update("pattern", value)}
            />
          </EditorGroup>
        ) : null}
        {supportsNumericConstraints(draft.dataType) ? (
          <EditorGroup legend="Numeric constraints">
            <EditorTextField
              label="Minimum"
              inputMode="decimal"
              value={draft.minimum}
              onChange={(value) => update("minimum", value)}
            />
            <EditorTextField
              label="Maximum"
              inputMode="decimal"
              value={draft.maximum}
              onChange={(value) => update("maximum", value)}
            />
          </EditorGroup>
        ) : null}
        {isSelectType(draft.dataType) ? (
          <label>
            <span>Options</span>
            <small>
              One durable `key | Label` pair per line. Removing an existing key
              archives it.
            </small>
            <Textarea
              rows={6}
              value={draft.optionsText}
              onChange={(event) =>
                update("optionsText", event.currentTarget.value)
              }
            />
          </label>
        ) : null}

        <EditorGroup legend="Audience and edit policy">
          <EditorToggle
            label="Visible to operators"
            checked={draft.operatorVisible}
            onChange={(value) => update("operatorVisible", value)}
          />
          <EditorToggle
            label="Operator create"
            checked={draft.operatorCreate}
            disabled={!draft.operatorVisible}
            onChange={(value) => update("operatorCreate", value)}
          />
          <EditorToggle
            label="Operator update"
            checked={draft.operatorUpdate}
            disabled={!draft.operatorVisible}
            onChange={(value) => update("operatorUpdate", value)}
          />
          <EditorToggle
            label="Visible to customers"
            checked={draft.customerVisible}
            onChange={(value) => update("customerVisible", value)}
          />
          <EditorToggle
            label="Customer create"
            checked={draft.customerCreate}
            disabled={!draft.customerVisible}
            onChange={(value) => update("customerCreate", value)}
          />
          <EditorToggle
            label="Customer update"
            checked={draft.customerUpdate}
            disabled={!draft.customerVisible}
            onChange={(value) => update("customerUpdate", value)}
          />
        </EditorGroup>

        <EditorGroup legend="Placement">
          <EditorToggle
            label="Create form"
            checked={draft.showInCreate}
            onChange={(value) => update("showInCreate", value)}
          />
          <EditorToggle
            label="Detail"
            checked={draft.showInDetail}
            onChange={(value) => update("showInDetail", value)}
          />
          <EditorToggle
            label="Lists"
            checked={draft.showInList}
            onChange={(value) => update("showInList", value)}
          />
          <EditorToggle
            label="Exports"
            checked={draft.showInExport}
            onChange={(value) => update("showInExport", value)}
          />
        </EditorGroup>

        <EditorGroup legend="Query capabilities">
          <EditorToggle
            label="Searchable"
            checked={supportsSearch(draft.dataType) && draft.searchable}
            disabled={!supportsSearch(draft.dataType)}
            onChange={(value) => update("searchable", value)}
          />
          <EditorToggle
            label="Filterable"
            checked={draft.dataType !== "structured_json" && draft.filterable}
            disabled={draft.dataType === "structured_json"}
            onChange={(value) => update("filterable", value)}
          />
          <EditorToggle
            label="Sortable"
            checked={supportsSort(draft.dataType) && draft.sortable}
            disabled={!supportsSort(draft.dataType)}
            onChange={(value) => update("sortable", value)}
          />
        </EditorGroup>

        {current ? (
          <section className="custom-field-editor__archive">
            <div>
              <Archive aria-hidden="true" />
              <span>
                <strong>Archive definition</strong>
                <small>
                  Historical values and revision pins remain intact.
                </small>
              </span>
            </div>
            <Label htmlFor="custom-field-archive-reason">Reason</Label>
            <Input
              id="custom-field-archive-reason"
              maxLength={500}
              value={archiveReason}
              onChange={(event) => onArchiveReason(event.currentTarget.value)}
            />
            <Button
              type="button"
              variant="destructive"
              disabled={saving}
              onClick={onArchive}
            >
              Archive
            </Button>
          </section>
        ) : null}
        <DialogFooter>
          <Button
            type="button"
            variant="outline"
            disabled={saving}
            onClick={onCancel}
          >
            Cancel
          </Button>
          <Button type="submit" disabled={saving}>
            {saving ? "Saving…" : current ? "Create revision" : "Create field"}
          </Button>
        </DialogFooter>
      </form>
    </DialogContent>
  );
}

function EditorGroup({
  children,
  legend,
}: {
  children: React.ReactNode;
  legend: string;
}): React.JSX.Element {
  return (
    <fieldset className="custom-field-editor__group">
      <legend>{legend}</legend>
      {children}
    </fieldset>
  );
}

function EditorTextField({
  disabled = false,
  hint,
  inputMode,
  label,
  maxLength,
  onChange,
  value,
}: {
  disabled?: boolean;
  hint?: string;
  inputMode?: React.HTMLAttributes<HTMLInputElement>["inputMode"];
  label: string;
  maxLength?: number;
  onChange: (value: string) => void;
  value: string;
}): React.JSX.Element {
  return (
    <label>
      <span>{label}</span>
      {hint ? <small>{hint}</small> : null}
      <Input
        disabled={disabled}
        inputMode={inputMode}
        maxLength={maxLength}
        value={value}
        onChange={(event) => onChange(event.currentTarget.value)}
      />
    </label>
  );
}

function EditorToggle({
  checked,
  disabled = false,
  label,
  onChange,
}: {
  checked: boolean;
  disabled?: boolean;
  label: string;
  onChange: (value: boolean) => void;
}): React.JSX.Element {
  return (
    <label className="custom-field-editor__toggle">
      <Checkbox
        checked={checked}
        disabled={disabled}
        onCheckedChange={(value) => onChange(value === true)}
      />
      {label}
    </label>
  );
}

function CatalogLoading(): React.JSX.Element {
  return (
    <div className="custom-field-admin__loading" role="status">
      <LoaderCircle className="is-spinning" aria-hidden="true" /> Loading
      current schema…
    </div>
  );
}

function CustomFieldBoundary({
  loading = false,
}: {
  loading?: boolean;
}): React.JSX.Element {
  return (
    <div
      className="content content--narrow custom-field-admin__boundary"
      role={loading ? "status" : undefined}
    >
      {loading ? (
        <LoaderCircle className="is-spinning" aria-hidden="true" />
      ) : (
        <ShieldX aria-hidden="true" />
      )}
      <p className="section-label">Live authorization boundary</p>
      <h1>
        {loading
          ? "Checking custom-field authority…"
          : "Custom fields are unavailable."}
      </h1>
      <p>
        {loading
          ? "The schema remains closed until current tenant authority is ready."
          : "An active tenant and tenant-scoped custom_field.read are required. Navigation is not authorization."}
      </p>
    </div>
  );
}

function parseDataType(value: string): CustomFieldDefinitionDraft["dataType"] {
  const result = customFieldDataTypes.find((dataType) => dataType === value);
  if (!result) throw new TypeError("Unsupported custom-field data type.");
  return result;
}

function describeCustomFieldError(error: unknown): string {
  if (error instanceof CustomFieldApiError) return error.message;
  return "The custom-field operation could not be completed.";
}

async function invalidateCatalog(
  queryClient: ReturnType<typeof useQueryClient>,
  tenantId: string,
): Promise<void> {
  await Promise.all([
    queryClient.invalidateQueries({
      queryKey: ["custom-field-administration", tenantId],
    }),
    queryClient.invalidateQueries({
      queryKey: ["custom-field-definitions", tenantId],
    }),
    queryClient.invalidateQueries({
      queryKey: ["ticket-column-catalog", tenantId],
    }),
  ]);
}

export const customFieldAdministrationRoutes = [
  {
    path: customFieldAdministrationRouteDescriptor.path.slice(1),
    Component: TenantCustomFieldAdministrationPage,
  },
] satisfies RouteObject[];
