import type {
  AlertMetadataReplaceRequest,
  CaseMetadataReplaceRequest,
} from "@periapsis/contracts";
import { Button } from "@periapsis/ui/components/ui/button";
import { Checkbox } from "@periapsis/ui/components/ui/checkbox";
import { Input } from "@periapsis/ui/components/ui/input";
import { Label } from "@periapsis/ui/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@periapsis/ui/components/ui/select";
import { Textarea } from "@periapsis/ui/components/ui/textarea";
import { FilePenLine, RefreshCw, Save, X } from "lucide-react";
import {
  useId,
  useLayoutEffect,
  useRef,
  useState,
  type FormEvent,
} from "react";

import { FormField } from "../components/form-field";
import {
  idempotencyKeyForPayload,
  type IdempotencyReference,
} from "../lib/payload-idempotency";
import type {
  OperatorTicketProjection,
  TicketKind,
  VersionedTicket,
} from "../lib/ticketing-api";
import {
  TicketMetadataApiError,
  type TicketMetadataApi,
} from "./ticket-metadata-api";
import {
  compareMetadataCodePoints,
  containsDisallowedMetadataControl,
  metadataCodePointLength,
  ticketMetadataTagPattern,
  trimMetadataEdges,
} from "./ticket-metadata-validation";

// oxlint-disable-next-line import/no-unassigned-import -- Vite extracts this component-owned stylesheet.
import "./ticket-metadata-panel.css";

interface MetadataDraft {
  category: string;
  classification: string;
  customerVisible: boolean;
  description: string;
  priority: "low" | "medium" | "high" | "urgent" | "critical";
  severity: "informational" | "low" | "medium" | "high" | "critical";
  summary: string;
  tags: string;
  title: string;
}

type MetadataField =
  "category" | "classification" | "description" | "summary" | "tags" | "title";
type MetadataErrors = Partial<Record<MetadataField, string>>;

interface NormalizedMetadataDraft {
  category: string;
  classification: string | null;
  customerVisible: boolean;
  description: string;
  priority: MetadataDraft["priority"];
  severity: MetadataDraft["severity"];
  summary: string;
  tags: string[];
  title: string;
}

function useTicketMetadataPanelState({
  api,
  canEdit,
  csrfToken,
  kind,
  onReloadLatest,
  sessionId,
  tenantId,
  ticket,
}: {
  api: TicketMetadataApi;
  canEdit: boolean;
  csrfToken: string;
  kind: TicketKind;
  onReloadLatest: () => Promise<boolean>;
  sessionId: string;
  tenantId: string;
  ticket: VersionedTicket<OperatorTicketProjection>;
}) {
  const id = useId();
  const authorizationKey = `${sessionId}:${tenantId}:${kind}:${ticket.value.id}:${ticket.etag}:${ticket.value.version}:${canEdit}:${csrfToken}`;
  const [draft, setDraft] = useState(() => draftFromTicket(kind, ticket));
  const [draftKey, setDraftKey] = useState(authorizationKey);
  const [editing, setEditing] = useState(false);
  const [errors, setErrors] = useState<MetadataErrors>({});
  const [problem, setProblem] = useState<string | null>(null);
  const [reloadRequired, setReloadRequired] = useState(false);
  const [saving, setSaving] = useState(false);
  const attempt = useRef<IdempotencyReference>({ current: null });
  const request = useRef<AbortController | null>(null);
  const authorizationEpoch = useRef({});
  const resetSnapshot = useRef(draft);
  // react-doctor-disable-next-line react-doctor/no-derived-state-effect -- The committed authority/ETag boundary atomically aborts stale writes, rotates their epoch and resets the editable draft; mounted concurrent-render tests cover it.
  useLayoutEffect(() => {
    authorizationEpoch.current = {};
    const snapshot = draftFromTicket(kind, ticket);
    resetSnapshot.current = snapshot;
    request.current?.abort();
    request.current = null;
    setDraft(snapshot);
    setDraftKey(authorizationKey);
    setEditing(false);
    setErrors({});
    setProblem(null);
    setReloadRequired(false);
    setSaving(false);
    attempt.current.current = null;
    return () => {
      authorizationEpoch.current = {};
      request.current?.abort();
    };
    // oxlint-disable-next-line react-hooks/exhaustive-deps -- The key binds the committed ticket ETag/version, coordinates, authority, session, and CSRF context.
  }, [authorizationKey]);
  const draftIsCurrent = draftKey === authorizationKey;
  const startEditing = (): void => {
    if (!canEdit || !draftIsCurrent || reloadRequired || saving) return;
    setDraft(resetSnapshot.current);
    setErrors({});
    setProblem(null);
    attempt.current.current = null;
    setEditing(true);
  };
  const cancelEditing = (): void => {
    request.current?.abort();
    request.current = null;
    setDraft(resetSnapshot.current);
    setErrors({});
    setProblem(null);
    setSaving(false);
    attempt.current.current = null;
    setEditing(false);
  };
  const reload = async (): Promise<void> => {
    request.current?.abort();
    const controller = new AbortController();
    request.current = controller;
    const token = authorizationEpoch.current;
    try {
      const reloaded = await onReloadLatest();
      if (
        authorizationEpoch.current !== token ||
        controller.signal.aborted ||
        request.current !== controller
      )
        return;
      if (reloaded) {
        // react-doctor-disable-next-line react-doctor/no-unowned-async-error-clear -- The authorization epoch, abort signal, and current controller above own this completion; overlapping reload coverage keeps a newer failure visible.
        setProblem(null);
        setReloadRequired(false);
      } else {
        setProblem("The latest ticket snapshot could not be loaded.");
        setReloadRequired(true);
      }
    } catch {
      if (
        authorizationEpoch.current !== token ||
        controller.signal.aborted ||
        request.current !== controller
      )
        return;
      setProblem("The latest ticket snapshot could not be loaded.");
      setReloadRequired(true);
    } finally {
      if (request.current === controller) request.current = null;
    }
  };
  const save = async (event: FormEvent<HTMLFormElement>): Promise<void> => {
    event.preventDefault();
    if (!canEdit || !draftIsCurrent || saving || reloadRequired) return;
    const normalized = normalizeMetadataDraft(kind, draft);
    setErrors(normalized.errors);
    setProblem(null);
    if (!normalized.value) return;

    const replacement = metadataReplacement(kind, normalized.value);
    const payload = {
      body: replacement.body,
      expectedVersion: ticket.value.version,
      kind: replacement.kind,
      operation: "replace-ticket-core-metadata",
      resourceId: ticket.value.id,
      sessionId,
      tenantId,
    };
    const idempotencyKey = idempotencyKeyForPayload(attempt.current, payload);
    const token = authorizationEpoch.current;
    request.current?.abort();
    const controller = new AbortController();
    request.current = controller;
    setSaving(true);
    try {
      await api.replace({
        ...replacement,
        csrfToken,
        etag: ticket.etag,
        expectedVersion: ticket.value.version,
        idempotencyKey,
        resourceId: ticket.value.id,
        signal: controller.signal,
        tenantId,
      });
      if (authorizationEpoch.current !== token) return;
      attempt.current.current = null;
      setEditing(false);
      setErrors({});
      const reloaded = await onReloadLatest();
      if (authorizationEpoch.current !== token) return;
      if (!reloaded) {
        setProblem(
          "Changes were saved, but the latest ticket snapshot could not be loaded. Reload before editing again.",
        );
        setReloadRequired(true);
      }
    } catch (error) {
      if (authorizationEpoch.current !== token || controller.signal.aborted) {
        return;
      }
      if (
        error instanceof TicketMetadataApiError &&
        (error.status === 412 || error.status === 428)
      ) {
        const reloaded = await onReloadLatest();
        if (authorizationEpoch.current !== token) return;
        setReloadRequired(!reloaded);
      }
      setProblem(metadataProblem(error));
    } finally {
      if (
        authorizationEpoch.current === token &&
        request.current === controller
      ) {
        request.current = null;
        // react-doctor-disable-next-line react-doctor/no-loading-flag-reset-outside-finally -- This is the finally block; ownership must match so an older request cannot clear a newer request's busy state.
        setSaving(false);
      }
    }
  };
  const titleId = `${id}-title`;
  const summaryId = `${id}-summary`;
  const descriptionId = `${id}-description`;
  const severityId = `${id}-severity`;
  const priorityId = `${id}-priority`;
  const categoryId = `${id}-category`;
  const classificationId = `${id}-classification`;
  const tagsId = `${id}-tags`;
  const visibleId = `${id}-customer-visible`;
  return {
    api,
    canEdit,
    csrfToken,
    kind,
    onReloadLatest,
    sessionId,
    tenantId,
    ticket,
    id,
    authorizationKey,
    draft,
    setDraft,
    draftKey,
    setDraftKey,
    editing,
    setEditing,
    errors,
    setErrors,
    problem,
    setProblem,
    reloadRequired,
    setReloadRequired,
    saving,
    setSaving,
    attempt,
    request,
    authorizationEpoch,
    resetSnapshot,
    draftIsCurrent,
    startEditing,
    cancelEditing,
    reload,
    save,
    titleId,
    summaryId,
    descriptionId,
    severityId,
    priorityId,
    categoryId,
    classificationId,
    tagsId,
    visibleId,
  };
}

export function TicketMetadataPanel(props: {
  api: TicketMetadataApi;
  canEdit: boolean;
  csrfToken: string;
  kind: TicketKind;
  onReloadLatest: () => Promise<boolean>;
  sessionId: string;
  tenantId: string;
  ticket: VersionedTicket<OperatorTicketProjection>;
}): React.JSX.Element {
  const state = useTicketMetadataPanelState(props);
  const {
    canEdit,
    kind,
    ticket,
    id,
    draft,
    setDraft,
    editing,
    errors,
    problem,
    reloadRequired,
    saving,
    draftIsCurrent,
    startEditing,
    cancelEditing,
    reload,
    save,
    titleId,
    summaryId,
    descriptionId,
    severityId,
    priorityId,
    categoryId,
    classificationId,
    tagsId,
    visibleId,
  } = state;

  return (
    <section className="ticket-metadata" aria-labelledby={`${id}-heading`}>
      <header className="ticket-metadata__heading">
        <div>
          <FilePenLine aria-hidden="true" />
          <span>
            <h3 id={`${id}-heading`}>Core details</h3>
            <small>Exact allowlist · audited replacement</small>
          </span>
        </div>
        <div className="ticket-metadata__controls">
          <span className="ticket-metadata__snapshot">
            Snapshot <strong>v{ticket.value.version}</strong>
          </span>
          {canEdit &&
          draftIsCurrent &&
          !editing &&
          !reloadRequired &&
          !saving ? (
            <Button type="button" variant="outline" onClick={startEditing}>
              <FilePenLine aria-hidden="true" /> Edit core details
            </Button>
          ) : null}
          {reloadRequired && draftIsCurrent ? (
            <Button
              type="button"
              variant="outline"
              onClick={() => void reload()}
            >
              <RefreshCw aria-hidden="true" /> Reload latest
            </Button>
          ) : null}
        </div>
      </header>

      {!canEdit ? (
        <p className="ticket-metadata__hint">
          Core details are read-only under the current live tenant authority.
        </p>
      ) : null}
      {problem && draftIsCurrent ? (
        <p className="ticket-metadata__problem" role="alert">
          {problem}
        </p>
      ) : null}

      {editing && canEdit && draftIsCurrent ? (
        <TicketMetadataEditor
          cancelEditing={cancelEditing}
          categoryId={categoryId}
          classificationId={classificationId}
          descriptionId={descriptionId}
          draft={draft}
          errors={errors}
          kind={kind}
          priorityId={priorityId}
          save={save}
          saving={saving}
          setDraft={setDraft}
          severityId={severityId}
          summaryId={summaryId}
          tagsId={tagsId}
          titleId={titleId}
          visibleId={visibleId}
        />
      ) : null}
    </section>
  );
}

function draftFromTicket(
  kind: TicketKind,
  ticket: VersionedTicket<OperatorTicketProjection>,
): MetadataDraft {
  const value = ticket.value;
  return {
    category: value.category,
    classification: value.classification ?? "",
    customerVisible: value.customerVisible,
    description: value.description,
    priority: value.priority,
    severity: value.severity,
    summary: kind === "case" && "summary" in value ? value.summary : "",
    tags: value.tags.join(", "),
    title: value.title,
  };
}

function normalizeMetadataDraft(
  kind: TicketKind,
  draft: MetadataDraft,
): { errors: MetadataErrors; value?: NormalizedMetadataDraft } {
  const classification = trimMetadataEdges(draft.classification);
  const value: NormalizedMetadataDraft = {
    category: trimMetadataEdges(draft.category),
    classification: classification === "" ? null : classification,
    customerVisible: draft.customerVisible,
    description: trimMetadataEdges(draft.description),
    priority: draft.priority,
    severity: draft.severity,
    summary: trimMetadataEdges(draft.summary),
    tags: [],
    title: trimMetadataEdges(draft.title),
  };
  const errors: MetadataErrors = {};
  validateText(value.title, 240, true, false, "Title", "title", errors);
  validateText(
    value.description,
    kind === "alert" ? 10_000 : 20_000,
    false,
    true,
    "Description",
    "description",
    errors,
  );
  if (kind === "case") {
    validateText(
      value.summary,
      2_000,
      false,
      true,
      "Summary",
      "summary",
      errors,
    );
  }
  validateText(
    value.category,
    120,
    true,
    false,
    "Category",
    "category",
    errors,
  );
  if (value.classification !== null) {
    validateText(
      value.classification,
      120,
      true,
      false,
      "Classification",
      "classification",
      errors,
    );
  }

  const rawTags = draft.tags
    .split(",")
    .map((tag) => tag.trim())
    .filter(Boolean);
  if (rawTags.length > 100) {
    errors.tags = "Use at most 100 tags.";
  } else if (new Set(rawTags).size !== rawTags.length) {
    errors.tags = "Each tag can appear only once.";
  } else {
    const invalid = rawTags.find((tag) => !ticketMetadataTagPattern.test(tag));
    if (invalid) {
      errors.tags = `Tag “${safeTagLabel(invalid)}” is invalid.`;
    } else {
      value.tags = rawTags.toSorted(compareMetadataCodePoints);
    }
  }
  return Object.keys(errors).length > 0 ? { errors } : { errors, value };
}

function metadataReplacement(
  kind: TicketKind,
  value: NormalizedMetadataDraft,
):
  | { body: AlertMetadataReplaceRequest; kind: "alert" }
  | { body: CaseMetadataReplaceRequest; kind: "case" } {
  const base = {
    category: value.category,
    classification: value.classification,
    customerVisible: value.customerVisible,
    description: value.description,
    priority: value.priority,
    severity: value.severity,
    tags: [...value.tags],
    title: value.title,
  };
  return kind === "alert"
    ? { body: base, kind }
    : { body: { ...base, summary: value.summary }, kind };
}

function validateText(
  value: string,
  maximumCharacters: number,
  required: boolean,
  multiline: boolean,
  label: string,
  field: MetadataField,
  errors: MetadataErrors,
): void {
  if (required && value.length === 0) {
    errors[field] = `${label} is required.`;
  } else if (metadataCodePointLength(value) > maximumCharacters) {
    errors[field] =
      `${label} must be at most ${maximumCharacters.toLocaleString()} characters.`;
  } else if (containsDisallowedMetadataControl(value, multiline)) {
    errors[field] = `${label} contains unsupported control characters.`;
  }
}

function safeTagLabel(value: string): string {
  return Array.from(value)
    .slice(0, 24)
    .join("")
    .replaceAll(/[\p{Cc}\p{Cf}]/gu, "?");
}

function metadataProblem(error: unknown): string {
  if (error instanceof TicketMetadataApiError) return error.message;
  return "Core ticket details could not be saved.";
}

function fieldDescription(
  id: string,
  error: string | undefined,
  hasHint = false,
): string | undefined {
  if (error) return `${id}-error`;
  return hasHint ? `${id}-hint` : undefined;
}

function optionalError(error: string | undefined): { error?: string } {
  return error ? { error } : {};
}

function sentenceCase(value: string): string {
  return value.charAt(0).toUpperCase() + value.slice(1).replaceAll("_", " ");
}

interface TicketMetadataEditorProps {
  cancelEditing: () => void;
  categoryId: string;
  classificationId: string;
  descriptionId: string;
  draft: MetadataDraft;
  errors: Partial<Record<MetadataField, string>>;
  kind: TicketKind;
  priorityId: string;
  save: (event: FormEvent<HTMLFormElement>) => Promise<void>;
  saving: boolean;
  setDraft: React.Dispatch<React.SetStateAction<MetadataDraft>>;
  severityId: string;
  summaryId: string;
  tagsId: string;
  titleId: string;
  visibleId: string;
}

function TicketMetadataEditor({
  cancelEditing,
  categoryId,
  classificationId,
  descriptionId,
  draft,
  errors,
  kind,
  priorityId,
  save,
  saving,
  setDraft,
  severityId,
  summaryId,
  tagsId,
  titleId,
  visibleId,
}: TicketMetadataEditorProps): React.JSX.Element {
  return (
    <form className="ticket-metadata__form" onSubmit={save} noValidate>
      <FormField
        {...optionalError(errors.title)}
        htmlFor={titleId}
        label="Title"
      >
        <Input
          aria-describedby={fieldDescription(titleId, errors.title)}
          aria-invalid={Boolean(errors.title)}
          id={titleId}
          maxLength={480}
          onChange={(event) =>
            setDraft((current) => ({
              ...current,
              title: event.target.value,
            }))
          }
          required
          value={draft.title}
        />
      </FormField>
      {kind === "case" ? (
        <FormField
          {...optionalError(errors.summary)}
          htmlFor={summaryId}
          label="Summary"
          optional
        >
          <Textarea
            aria-describedby={fieldDescription(summaryId, errors.summary)}
            aria-invalid={Boolean(errors.summary)}
            id={summaryId}
            maxLength={4_000}
            onChange={(event) =>
              setDraft((current) => ({
                ...current,
                summary: event.target.value,
              }))
            }
            rows={3}
            value={draft.summary}
          />
        </FormField>
      ) : null}
      <div className="ticket-metadata__wide-field">
        <FormField
          {...optionalError(errors.description)}
          htmlFor={descriptionId}
          label="Description"
          optional
        >
          <Textarea
            aria-describedby={fieldDescription(
              descriptionId,
              errors.description,
            )}
            aria-invalid={Boolean(errors.description)}
            id={descriptionId}
            maxLength={kind === "alert" ? 20_000 : 40_000}
            onChange={(event) =>
              setDraft((current) => ({
                ...current,
                description: event.target.value,
              }))
            }
            rows={5}
            value={draft.description}
          />
        </FormField>
      </div>
      <FormField htmlFor={severityId} label="Severity">
        <Select
          value={draft.severity}
          onValueChange={(value: MetadataDraft["severity"]) =>
            setDraft((current) => ({ ...current, severity: value }))
          }
        >
          <SelectTrigger id={severityId} aria-label="Severity">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {["informational", "low", "medium", "high", "critical"].map(
              (value) => (
                <SelectItem key={value} value={value}>
                  {sentenceCase(value)}
                </SelectItem>
              ),
            )}
          </SelectContent>
        </Select>
      </FormField>
      <FormField htmlFor={priorityId} label="Priority">
        <Select
          value={draft.priority}
          onValueChange={(value: MetadataDraft["priority"]) =>
            setDraft((current) => ({ ...current, priority: value }))
          }
        >
          <SelectTrigger id={priorityId} aria-label="Priority">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {["low", "medium", "high", "urgent", "critical"].map((value) => (
              <SelectItem key={value} value={value}>
                {sentenceCase(value)}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </FormField>
      <FormField
        {...optionalError(errors.category)}
        htmlFor={categoryId}
        label="Category"
      >
        <Input
          aria-describedby={fieldDescription(categoryId, errors.category)}
          aria-invalid={Boolean(errors.category)}
          id={categoryId}
          maxLength={240}
          onChange={(event) =>
            setDraft((current) => ({
              ...current,
              category: event.target.value,
            }))
          }
          required
          value={draft.category}
        />
      </FormField>
      <FormField
        {...optionalError(errors.classification)}
        hint="Leave blank to remove the classification."
        htmlFor={classificationId}
        label="Classification"
        optional
      >
        <Input
          aria-describedby={fieldDescription(
            classificationId,
            errors.classification,
            true,
          )}
          aria-invalid={Boolean(errors.classification)}
          id={classificationId}
          maxLength={240}
          onChange={(event) =>
            setDraft((current) => ({
              ...current,
              classification: event.target.value,
            }))
          }
          value={draft.classification}
        />
      </FormField>
      <div className="ticket-metadata__wide-field">
        <FormField
          {...optionalError(errors.tags)}
          hint="Comma-separated canonical tags; order is normalized before save."
          htmlFor={tagsId}
          label="Tags"
          optional
        >
          <Input
            aria-describedby={fieldDescription(tagsId, errors.tags, true)}
            aria-invalid={Boolean(errors.tags)}
            id={tagsId}
            onChange={(event) =>
              setDraft((current) => ({
                ...current,
                tags: event.target.value,
              }))
            }
            value={draft.tags}
          />
        </FormField>
      </div>
      <div className="ticket-metadata__visibility">
        <Checkbox
          checked={draft.customerVisible}
          id={visibleId}
          onCheckedChange={(checked) =>
            setDraft((current) => ({
              ...current,
              customerVisible: checked === true,
            }))
          }
        />
        <span>
          <Label htmlFor={visibleId}>Customer visible</Label>
          <small>
            Controls the ticket projection, not field-level authority.
          </small>
        </span>
      </div>
      <div className="ticket-metadata__actions">
        <Button
          type="button"
          variant="outline"
          disabled={saving}
          onClick={cancelEditing}
        >
          <X aria-hidden="true" /> Cancel
        </Button>
        <Button type="submit" disabled={saving}>
          <Save aria-hidden="true" />
          {saving ? "Saving core details…" : "Save core details"}
        </Button>
      </div>
    </form>
  );
}
