import type {
  CommentCreateRequest,
  CommentEditRequest,
  TenantPermissionKey,
} from "@periapsis/contracts";
import { Button } from "@periapsis/ui/components/ui/button";
import { Checkbox } from "@periapsis/ui/components/ui/checkbox";
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
import {
  useInfiniteQuery,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import {
  Clock3,
  History,
  LockKeyhole,
  Paperclip,
  Pencil,
  ShieldCheck,
} from "lucide-react";
import {
  memo,
  useCallback,
  useLayoutEffect,
  useRef,
  useState,
  type FormEvent,
} from "react";

import { useSession } from "../auth/session-context";
import { useTenantAuthority } from "../auth/tenant-authority-context";
import { FocusedError } from "../components/focused-error";
import {
  hasGoTrimSpaceAtEdge,
  hasUnpairedSurrogate,
} from "../lib/canonical-display-name";
import {
  idempotencyKeyForPayload,
  type IdempotencyReference,
} from "../lib/payload-idempotency";
import { TenantInstant } from "../lib/tenant-date-time-context";
import {
  hasBidiControlCharacters,
  hasControlCharacters,
  hasForbiddenCommentMarkdownCharacters,
} from "../lib/text-validation";
import {
  describeTicketingError,
  TicketingApiError,
  type TicketComment,
  type TicketCommentPreview,
  type TicketKind,
} from "../lib/ticketing-api";
import { SafeMarkdown } from "./safe-markdown";
import { useTicketingApi } from "./ticketing-context";
import { hasAnyTicketPermission, humanizeKey } from "./ticketing-model";

type ComposerMode = "preview" | "write";
type OperatorComment = Extract<TicketComment, { projection: "operator" }>;

interface Draft {
  attachmentText: string;
  bodyMarkdown: string;
  mentionedMembershipIds: Set<string>;
  visibility: "private" | "public";
}

const emptyDraft = (): Draft => ({
  attachmentText: "",
  bodyMarkdown: "",
  mentionedMembershipIds: new Set(),
  visibility: "public",
});

type MentionSelectionChange = (membershipId: string, checked: boolean) => void;

function withMentionSelection(
  current: Draft,
  membershipId: string,
  checked: boolean,
): Draft {
  const mentionedMembershipIds = new Set(current.mentionedMembershipIds);
  if (checked) {
    if (
      mentionedMembershipIds.size < 50 ||
      mentionedMembershipIds.has(membershipId)
    ) {
      mentionedMembershipIds.add(membershipId);
    }
  } else {
    mentionedMembershipIds.delete(membershipId);
  }
  return { ...current, mentionedMembershipIds };
}

function useTicketCommentPanelState({
  kind,
  projection,
  resourceId,
  tenantId,
}: {
  kind: TicketKind;
  projection: "customer" | "operator";
  resourceId: string;
  tenantId: string;
}) {
  const api = useTicketingApi();
  const { session } = useSession();
  const authority = useTenantAuthority();
  const queryClient = useQueryClient();
  const [draft, setDraft] = useState<Draft>(emptyDraft);
  const [composerMode, setComposerMode] = useState<ComposerMode>("write");
  const [preview, setPreview] = useState<TicketCommentPreview | null>(null);
  const [selectedComment, setSelectedComment] =
    useState<OperatorComment | null>(null);
  const [dialogMode, setDialogMode] = useState<"edit" | "history" | null>(null);
  const [editDraft, setEditDraft] = useState<Draft>(emptyDraft);
  const [editReason, setEditReason] = useState("");
  const [editPreview, setEditPreview] = useState<TicketCommentPreview | null>(
    null,
  );
  const [pending, setPending] = useState<"create" | "edit" | "preview" | null>(
    null,
  );
  const [error, setError] = useState<string | null>(null);
  const [editError, setEditError] = useState<string | null>(null);
  const attemptRef = useRef<IdempotencyReference["current"]>(null);
  const editAttemptRef = useRef<IdempotencyReference["current"]>(null);
  const controllerRef = useRef<AbortController | null>(null);
  const changeMention = useCallback<MentionSelectionChange>(
    (membershipId, checked) => {
      setDraft((current) =>
        withMentionSelection(current, membershipId, checked),
      );
      setPreview(null);
    },
    [],
  );
  const changeEditMention = useCallback<MentionSelectionChange>(
    (membershipId, checked) => {
      setEditDraft((current) =>
        withMentionSelection(current, membershipId, checked),
      );
      setEditPreview(null);
    },
    [],
  );
  const ticketReadPermission = `${kind}.read` as TenantPermissionKey;
  const readPermission = `${kind}.comment.read` as TenantPermissionKey;
  const publicPermission = `${kind}.comment.public` as TenantPermissionKey;
  const privatePermission = `${kind}.comment.private` as TenantPermissionKey;
  const isOperator = projection === "operator";
  const canRead =
    isOperator &&
    hasAnyTicketPermission(authority.hasPermission, ticketReadPermission) &&
    hasAnyTicketPermission(authority.hasPermission, readPermission);
  const canCommentPublic =
    canRead &&
    hasAnyTicketPermission(authority.hasPermission, publicPermission);
  const canCommentPrivate =
    isOperator &&
    hasAnyTicketPermission(authority.hasPermission, privatePermission);
  const canWritePrivate = canCommentPublic && canCommentPrivate;
  const currentMembershipId = authority.authority?.membershipId;
  const boundary = JSON.stringify([
    authority.pairKey,
    authority.revision,
    authority.authority?.evaluatedAt ?? null,
    session.id,
    session.activeTenantId,
    session.csrfToken,
    tenantId,
    kind,
    resourceId,
    canRead,
    canCommentPublic,
    canCommentPrivate,
  ]);
  const boundaryRef = useRef(boundary);
  useLayoutEffect(() => {
    boundaryRef.current = boundary;
    controllerRef.current?.abort();
    controllerRef.current = null;
    attemptRef.current = null;
    editAttemptRef.current = null;
    setPending(null);
    setError(null);
    setEditError(null);
    setPreview(null);
    setEditPreview(null);
    setSelectedComment(null);
    setDialogMode(null);
    setDraft(emptyDraft());
    setEditDraft(emptyDraft());
    setEditReason("");
    setComposerMode("write");
    return () => controllerRef.current?.abort();
  }, [boundary]);
  {
    if (!canWritePrivate && draft.visibility === "private") {
      setDraft((current) => ({ ...current, visibility: "public" }));
      setPreview(null);
    }
  }
  const comments = useInfiniteQuery({
    enabled: canRead,
    initialPageParam: undefined as string | undefined,
    queryKey: ["ticket-comments", boundary],
    queryFn: ({ pageParam, signal }) =>
      api.listComments(kind, tenantId, resourceId, pageParam, signal),
    getNextPageParam: (page) => page.nextCursor,
  });
  const candidates = useQuery({
    enabled: canCommentPublic,
    queryKey: ["ticket-comment-mentions", boundary],
    queryFn: ({ signal }) =>
      api.listCommentMentionCandidates({
        kind,
        resourceId,
        signal,
        tenantId,
      }),
  });
  const history = useQuery({
    enabled: canRead && selectedComment !== null && dialogMode !== null,
    queryKey: ["ticket-comment-history", boundary, selectedComment?.id],
    queryFn: ({ signal }) =>
      api.listCommentRevisions({
        commentId: selectedComment!.id,
        kind,
        resourceId,
        signal,
        tenantId,
      }),
  });
  const items = comments.data?.pages.flatMap((page) => page.items) ?? [];
  return {
    kind,
    projection,
    resourceId,
    tenantId,
    api,
    session,
    authority,
    queryClient,
    draft,
    setDraft,
    composerMode,
    setComposerMode,
    preview,
    setPreview,
    selectedComment,
    setSelectedComment,
    dialogMode,
    setDialogMode,
    editDraft,
    setEditDraft,
    editReason,
    setEditReason,
    editPreview,
    setEditPreview,
    pending,
    setPending,
    error,
    setError,
    editError,
    setEditError,
    attemptRef,
    editAttemptRef,
    controllerRef,
    changeMention,
    changeEditMention,
    ticketReadPermission,
    readPermission,
    publicPermission,
    privatePermission,
    isOperator,
    canRead,
    canCommentPublic,
    canCommentPrivate,
    canWritePrivate,
    currentMembershipId,
    boundary,
    boundaryRef,
    comments,
    candidates,
    history,
    items,
  };
}

function createTicketCommentPanelActions({
  kind,
  resourceId,
  tenantId,
  api,
  session,
  queryClient,
  draft,
  setDraft,
  setComposerMode,
  setPreview,
  selectedComment,
  setSelectedComment,
  setDialogMode,
  editDraft,
  setEditDraft,
  editReason,
  setEditReason,
  setEditPreview,
  setPending,
  setError,
  setEditError,
  attemptRef,
  editAttemptRef,
  controllerRef,
  canCommentPublic,
  canCommentPrivate,
  currentMembershipId,
  boundary,
  boundaryRef,
  comments,
  history,
}: ReturnType<typeof useTicketCommentPanelState>) {
  function beginRequest(): {
    controller: AbortController;
    requestedBoundary: string;
  } {
    controllerRef.current?.abort();
    const controller = new AbortController();
    controllerRef.current = controller;
    return { controller, requestedBoundary: boundary };
  }
  function requestStillCurrent(
    controller: AbortController,
    requestedBoundary: string,
  ): boolean {
    return (
      !controller.signal.aborted && boundaryRef.current === requestedBoundary
    );
  }
  async function previewDraft(value: Draft, editing: boolean): Promise<void> {
    const parsed = parseDraft(value, canCommentPublic, canCommentPrivate);
    if (!parsed.ok) {
      if (editing) setEditError(parsed.error);
      else setError(parsed.error);
      return;
    }
    const { controller, requestedBoundary } = beginRequest();
    setPending("preview");
    if (editing) setEditError(null);
    else setError(null);
    try {
      const result = await api.previewComment({
        body: parsed.body,
        csrfToken: session.csrfToken,
        kind,
        resourceId,
        signal: controller.signal,
        tenantId,
      });
      if (!requestStillCurrent(controller, requestedBoundary)) return;
      if (editing) setEditPreview(result);
      else {
        setPreview(result);
        setComposerMode("preview");
      }
    } catch (caught) {
      if (!requestStillCurrent(controller, requestedBoundary)) return;
      const message = describeTicketingError(
        caught,
        "The server could not preview this comment.",
      );
      if (editing) setEditError(message);
      else setError(message);
    } finally {
      if (requestStillCurrent(controller, requestedBoundary)) setPending(null);
    }
  }
  async function submit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const parsed = parseDraft(draft, canCommentPublic, canCommentPrivate);
    if (!parsed.ok) {
      setError(parsed.error);
      return;
    }
    const idempotencyKey = idempotencyKeyForPayload(attemptRef, {
      kind,
      operation: "comment.create",
      request: parsed.body,
      resourceId,
      tenantId,
    });
    const { controller, requestedBoundary } = beginRequest();
    setError(null);
    setPending("create");
    try {
      await api.createComment({
        body: parsed.body,
        csrfToken: session.csrfToken,
        idempotencyKey,
        kind,
        resourceId,
        signal: controller.signal,
        tenantId,
      });
      if (!requestStillCurrent(controller, requestedBoundary)) return;
      attemptRef.current = null;
      setDraft(emptyDraft());
      setPreview(null);
      setComposerMode("write");
      await comments.refetch();
      void queryClient.invalidateQueries({
        queryKey: ["ticket-activity", kind, tenantId, resourceId],
      });
    } catch (caught) {
      if (!requestStillCurrent(controller, requestedBoundary)) return;
      setError(
        describeTicketingError(caught, "The comment could not be posted."),
      );
    } finally {
      if (requestStillCurrent(controller, requestedBoundary)) setPending(null);
    }
  }
  async function saveEdit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (
      !selectedComment ||
      !canEditComment(
        selectedComment,
        currentMembershipId,
        canCommentPublic,
        canCommentPrivate,
      )
    ) {
      setEditError("This comment is no longer editable by the current author.");
      return;
    }
    const parsed = parseDraft(editDraft, canCommentPublic, canCommentPrivate);
    if (!parsed.ok) {
      setEditError(parsed.error);
      return;
    }
    const reason = editReason.trim();
    if (
      !reason ||
      Array.from(reason).length > 500 ||
      hasControlCharacters(reason) ||
      hasBidiControlCharacters(reason) ||
      hasUnpairedSurrogate(reason) ||
      /<\/?[A-Za-z]/u.test(reason)
    ) {
      setEditError("Add a plain-text edit reason of at most 500 characters.");
      return;
    }
    const body: CommentEditRequest = {
      bodyMarkdown: parsed.body.bodyMarkdown,
      reason,
      ...(parsed.body.attachmentIds
        ? { attachmentIds: parsed.body.attachmentIds }
        : {}),
      ...(parsed.body.mentionedMembershipIds
        ? { mentionedMembershipIds: parsed.body.mentionedMembershipIds }
        : {}),
    };
    const etag = `"comment-r${selectedComment.revision}"`;
    const idempotencyKey = idempotencyKeyForPayload(editAttemptRef, {
      body,
      commentId: selectedComment.id,
      etag,
      kind,
      operation: "comment.edit",
      resourceId,
      tenantId,
    });
    const { controller, requestedBoundary } = beginRequest();
    setEditError(null);
    setPending("edit");
    try {
      await api.editComment({
        body,
        commentId: selectedComment.id,
        csrfToken: session.csrfToken,
        etag,
        idempotencyKey,
        kind,
        resourceId,
        signal: controller.signal,
        tenantId,
      });
      if (!requestStillCurrent(controller, requestedBoundary)) return;
      editAttemptRef.current = null;
      await Promise.all([comments.refetch(), history.refetch()]);
      if (!requestStillCurrent(controller, requestedBoundary)) return;
      setDialogMode("history");
      setEditPreview(null);
    } catch (caught) {
      if (!requestStillCurrent(controller, requestedBoundary)) return;
      if (
        caught instanceof TicketingApiError &&
        (caught.status === 412 || caught.status === 428)
      ) {
        editAttemptRef.current = null;
        const [freshComments] = await Promise.all([
          comments.refetch(),
          history.refetch(),
        ]);
        if (!requestStillCurrent(controller, requestedBoundary)) return;
        const latest = freshComments.data?.pages
          .flatMap((page) => page.items)
          .find(
            (comment): comment is OperatorComment =>
              comment.id === selectedComment.id &&
              comment.projection === "operator",
          );
        if (latest) {
          setSelectedComment(latest);
          setEditDraft(draftFromComment(latest));
          setEditPreview(null);
        }
        setEditError(
          "This comment changed on the server. Review the latest revision before retrying.",
        );
      } else {
        setEditError(
          describeTicketingError(
            caught,
            "The comment edit could not be saved.",
          ),
        );
      }
    } finally {
      if (requestStillCurrent(controller, requestedBoundary)) setPending(null);
    }
  }
  function openComment(comment: TicketComment, mode: "edit" | "history"): void {
    if (comment.projection !== "operator") return;
    setSelectedComment(comment);
    setDialogMode(mode);
    setEditError(null);
    setEditPreview(null);
    editAttemptRef.current = null;
    setEditReason("");
    setEditDraft(draftFromComment(comment));
  }
  return {
    beginRequest,
    requestStillCurrent,
    previewDraft,
    submit,
    saveEdit,
    openComment,
  };
}

export function TicketCommentPanel(props: {
  kind: TicketKind;
  projection: "customer" | "operator";
  resourceId: string;
  tenantId: string;
}): React.JSX.Element {
  const state = useTicketCommentPanelState(props);
  const {
    draft,
    setDraft,
    composerMode,
    setComposerMode,
    preview,
    setPreview,
    selectedComment,
    setSelectedComment,
    dialogMode,
    setDialogMode,
    editDraft,
    setEditDraft,
    editReason,
    setEditReason,
    editPreview,
    setEditPreview,
    pending,
    error,
    editError,
    controllerRef,
    changeMention,
    changeEditMention,
    canRead,
    canCommentPublic,
    canCommentPrivate,
    canWritePrivate,
    currentMembershipId,
    comments,
    candidates,
    history,
    items,
  } = state;
  if (!canRead) {
    return (
      <div
        id="ticket-panel-comments"
        role="tabpanel"
        aria-labelledby="ticket-tab-comments"
      >
        <p role="alert">
          Comment access is not available for this operator boundary.
        </p>
      </div>
    );
  }
  const { previewDraft, submit, saveEdit, openComment } =
    createTicketCommentPanelActions(state);
  return (
    <div
      id="ticket-panel-comments"
      role="tabpanel"
      aria-labelledby="ticket-tab-comments"
      className="ticket-comments-panel"
    >
      {canCommentPublic ? (
        <TicketCommentComposer
          candidates={candidates}
          canWritePrivate={canWritePrivate}
          changeMention={changeMention}
          composerMode={composerMode}
          draft={draft}
          error={error}
          pending={pending}
          preview={preview}
          previewDraft={previewDraft}
          setComposerMode={setComposerMode}
          setDraft={setDraft}
          setPreview={setPreview}
          submit={submit}
        />
      ) : null}
      {comments.isPending ? <p aria-live="polite">Loading comments…</p> : null}
      {comments.isError ? (
        <FocusedError
          title="Comments unavailable"
          message={describeTicketingError(
            comments.error,
            "Comments could not be loaded.",
          )}
        />
      ) : null}
      {!comments.isPending && !comments.isError && items.length === 0 ? (
        <p>No comments are visible.</p>
      ) : null}
      <div className="ticket-comment-list">
        {items.map((comment) => (
          <CommentCard
            comment={comment}
            key={comment.id}
            onEdit={() => openComment(comment, "edit")}
            onHistory={() => openComment(comment, "history")}
            showEdit={
              comment.projection === "operator" &&
              canEditComment(
                comment,
                currentMembershipId,
                canCommentPublic,
                canCommentPrivate,
              )
            }
          />
        ))}
      </div>
      {comments.hasNextPage ? (
        <Button
          variant="outline"
          size="sm"
          disabled={comments.isFetchingNextPage}
          onClick={() => void comments.fetchNextPage()}
        >
          {comments.isFetchingNextPage ? "Loading more…" : "Load more"}
        </Button>
      ) : null}
      <TicketCommentDialog
        candidates={candidates}
        changeEditMention={changeEditMention}
        controllerRef={controllerRef}
        dialogMode={dialogMode}
        editDraft={editDraft}
        editError={editError}
        editPreview={editPreview}
        editReason={editReason}
        history={history}
        pending={pending}
        previewDraft={previewDraft}
        saveEdit={saveEdit}
        selectedComment={selectedComment}
        setDialogMode={setDialogMode}
        setEditDraft={setEditDraft}
        setEditPreview={setEditPreview}
        setEditReason={setEditReason}
        setSelectedComment={setSelectedComment}
      />
    </div>
  );
}

function parseDraft(
  draft: Draft,
  canCommentPublic: boolean,
  canCommentPrivate: boolean,
): { ok: true; body: CommentCreateRequest } | { ok: false; error: string } {
  const bodyMarkdown = draft.bodyMarkdown;
  if (bodyMarkdown.length === 0)
    return { ok: false, error: "Write a comment before continuing." };
  if (
    hasGoTrimSpaceAtEdge(bodyMarkdown) ||
    Array.from(bodyMarkdown).length > 20_000 ||
    hasForbiddenCommentMarkdownCharacters(bodyMarkdown) ||
    hasUnpairedSurrogate(bodyMarkdown)
  ) {
    return {
      ok: false,
      error: "Comments must contain at most 20000 valid Unicode characters.",
    };
  }
  if (draft.visibility === "public" && !canCommentPublic) {
    return {
      ok: false,
      error: "Public comments are not available at this authority boundary.",
    };
  }
  if (
    draft.visibility === "private" &&
    (!canCommentPublic || !canCommentPrivate)
  ) {
    return {
      ok: false,
      error: "Private comments are not available at this authority boundary.",
    };
  }
  const attachments = parseAttachmentIds(draft.attachmentText);
  if (!attachments.ok) return { ok: false, error: attachments.error };
  const mentionedMembershipIds = [...draft.mentionedMembershipIds].toSorted();
  if (mentionedMembershipIds.length > 50) {
    return { ok: false, error: "Mention at most 50 ticket operators." };
  }
  return {
    ok: true,
    body: {
      bodyMarkdown,
      visibility: draft.visibility,
      ...(attachments.ids.length ? { attachmentIds: attachments.ids } : {}),
      ...(mentionedMembershipIds.length ? { mentionedMembershipIds } : {}),
    },
  };
}

function parseAttachmentIds(
  value: string,
): { ok: true; ids: string[] } | { ok: false; error: string } {
  const ids = value
    .split(/[\s,]+/u)
    .map((item) => item.trim())
    .filter(Boolean);
  if (ids.length > 20)
    return { ok: false, error: "Select at most 20 attachment IDs." };
  const unique = new Set(ids);
  if (unique.size !== ids.length)
    return { ok: false, error: "Attachment IDs must be unique." };
  if (
    ids.some(
      (id) =>
        !/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(
          id,
        ),
    )
  ) {
    return {
      ok: false,
      error: "Attachment IDs must be canonical UUIDv7 values.",
    };
  }
  return { ok: true, ids: ids.toSorted() };
}

function CommentAttachmentInput({
  id = "ticket-comment-attachments",
  onChange,
  value,
}: {
  id?: string;
  onChange: (value: string) => void;
  value: string;
}): React.JSX.Element {
  return (
    <div>
      <Label htmlFor={id}>Attachment IDs</Label>
      <Textarea
        id={id}
        rows={2}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder="Up to 20 authorized UUIDv7 IDs, separated by spaces or lines"
      />
      <small>
        <Paperclip aria-hidden="true" /> The server rechecks the same ticket and
        public visibility.
      </small>
    </div>
  );
}

function MentionPicker({
  candidates,
  onChange,
  selected,
}: {
  candidates: Array<{ displayName: string; membershipId: string }>;
  onChange: MentionSelectionChange;
  selected: Set<string>;
}): React.JSX.Element {
  if (candidates.length === 0) return <p>No eligible operator mentions.</p>;
  const limitReached = selected.size >= 50;
  return (
    <fieldset>
      <legend>Mention ticket operators</legend>
      {candidates.map((candidate) => (
        <MentionCandidate
          key={candidate.membershipId}
          membershipId={candidate.membershipId}
          displayName={candidate.displayName}
          checked={selected.has(candidate.membershipId)}
          disabled={limitReached && !selected.has(candidate.membershipId)}
          onChange={onChange}
        />
      ))}
      {limitReached ? (
        <small role="status">
          The maximum of 50 operator mentions is selected.
        </small>
      ) : null}
    </fieldset>
  );
}

const MentionCandidate = memo(function MentionCandidate({
  membershipId,
  displayName,
  checked,
  disabled,
  onChange,
}: {
  membershipId: string;
  displayName: string;
  checked: boolean;
  disabled: boolean;
  onChange: MentionSelectionChange;
}): React.JSX.Element {
  return (
    <label>
      <Checkbox
        checked={checked}
        disabled={disabled}
        onCheckedChange={(value) => onChange(membershipId, value === true)}
      />
      {displayName}
    </label>
  );
});

function CommentPreview({
  preview,
}: {
  preview: TicketCommentPreview;
}): React.JSX.Element {
  return (
    <section aria-label="Accepted comment preview">
      <SafeMarkdown markdown={preview.bodyMarkdown} />
      {preview.attachments.length ? (
        <p>{preview.attachments.length} attachment(s) accepted.</p>
      ) : null}
      {preview.mentions.length ? (
        <p>{preview.mentions.length} operator mention(s) accepted.</p>
      ) : null}
    </section>
  );
}

function CommentCard({
  comment,
  onEdit,
  onHistory,
  showEdit,
}: {
  comment: TicketComment;
  onEdit: () => void;
  onHistory: () => void;
  showEdit: boolean;
}): React.JSX.Element {
  return (
    <article className="ticket-comment-card">
      <header>
        <div>
          <span className="ticket-comment-card__avatar" aria-hidden="true">
            {comment.author.displayName.slice(0, 1).toUpperCase()}
          </span>
          <span>
            <strong>{comment.author.displayName}</strong>
            <small>{humanizeKey(comment.origin)}</small>
          </span>
        </div>
        <span>
          {comment.visibility === "private" ? (
            <LockKeyhole aria-hidden="true" />
          ) : null}
          {humanizeKey(comment.visibility)} ·{" "}
          <TenantInstant value={comment.createdAt} />
        </span>
      </header>
      <SafeMarkdown markdown={comment.bodyMarkdown} />
      {comment.attachments.length ? (
        <ul aria-label="Comment attachments">
          {comment.attachments.map((attachment) => (
            <li key={attachment.id}>{attachment.originalFilename}</li>
          ))}
        </ul>
      ) : null}
      {comment.projection === "operator" && comment.mentions.length ? (
        <p>
          Mentions:{" "}
          {comment.mentions.map((mention) => mention.displayName).join(", ")}
        </p>
      ) : null}
      <footer>
        <Button type="button" size="sm" variant="ghost" onClick={onHistory}>
          <History aria-hidden="true" /> History
        </Button>
        {showEdit ? (
          <Button type="button" size="sm" variant="outline" onClick={onEdit}>
            <Pencil aria-hidden="true" /> Edit
          </Button>
        ) : null}
        <small>
          <Clock3 aria-hidden="true" /> Editable until{" "}
          <TenantInstant value={comment.editableUntil} />
        </small>
      </footer>
    </article>
  );
}

function canEditComment(
  comment: OperatorComment,
  currentMembershipId: string | undefined,
  canCommentPublic: boolean,
  canCommentPrivate: boolean,
): boolean {
  return (
    comment.canEdit &&
    comment.origin === "api" &&
    comment.author.audience === "operator" &&
    comment.author.membershipId === currentMembershipId &&
    Date.parse(comment.editableUntil) > Date.now() &&
    (comment.visibility === "public"
      ? canCommentPublic
      : canCommentPublic && canCommentPrivate)
  );
}

function draftFromComment(comment: OperatorComment): Draft {
  return {
    attachmentText: comment.attachments.map((item) => item.id).join("\n"),
    bodyMarkdown: comment.bodyMarkdown,
    mentionedMembershipIds: new Set(
      comment.mentions.map((mention) => mention.membershipId),
    ),
    visibility: comment.visibility,
  };
}

interface TicketCommentDialogProps {
  candidates: ReturnType<typeof useTicketCommentPanelState>["candidates"];
  changeEditMention: ReturnType<
    typeof useTicketCommentPanelState
  >["changeEditMention"];
  controllerRef: ReturnType<typeof useTicketCommentPanelState>["controllerRef"];
  dialogMode: ReturnType<typeof useTicketCommentPanelState>["dialogMode"];
  editDraft: ReturnType<typeof useTicketCommentPanelState>["editDraft"];
  editError: ReturnType<typeof useTicketCommentPanelState>["editError"];
  editPreview: ReturnType<typeof useTicketCommentPanelState>["editPreview"];
  editReason: ReturnType<typeof useTicketCommentPanelState>["editReason"];
  history: ReturnType<typeof useTicketCommentPanelState>["history"];
  pending: ReturnType<typeof useTicketCommentPanelState>["pending"];
  previewDraft: ReturnType<
    typeof createTicketCommentPanelActions
  >["previewDraft"];
  saveEdit: ReturnType<typeof createTicketCommentPanelActions>["saveEdit"];
  selectedComment: ReturnType<
    typeof useTicketCommentPanelState
  >["selectedComment"];
  setDialogMode: ReturnType<typeof useTicketCommentPanelState>["setDialogMode"];
  setEditDraft: ReturnType<typeof useTicketCommentPanelState>["setEditDraft"];
  setEditPreview: ReturnType<
    typeof useTicketCommentPanelState
  >["setEditPreview"];
  setEditReason: ReturnType<typeof useTicketCommentPanelState>["setEditReason"];
  setSelectedComment: ReturnType<
    typeof useTicketCommentPanelState
  >["setSelectedComment"];
}

function TicketCommentDialog({
  candidates,
  changeEditMention,
  controllerRef,
  dialogMode,
  editDraft,
  editError,
  editPreview,
  editReason,
  history,
  pending,
  previewDraft,
  saveEdit,
  selectedComment,
  setDialogMode,
  setEditDraft,
  setEditPreview,
  setEditReason,
  setSelectedComment,
}: TicketCommentDialogProps): React.JSX.Element {
  return (
    <Dialog
      open={selectedComment !== null && dialogMode !== null}
      onOpenChange={(open) => {
        if (!open) {
          controllerRef.current?.abort();
          controllerRef.current = null;
          setSelectedComment(null);
          setDialogMode(null);
        }
      }}
    >
      <DialogContent>
        <DialogHeader>
          <DialogTitle>
            {dialogMode === "edit" ? "Edit your comment" : "Comment history"}
          </DialogTitle>
          <DialogDescription>
            Edits append immutable revisions. Visibility cannot change and there
            is no delete or override.
          </DialogDescription>
        </DialogHeader>
        {dialogMode === "edit" && selectedComment ? (
          <form onSubmit={(event) => void saveEdit(event)}>
            {editError ? (
              <FocusedError title="Comment not edited" message={editError} />
            ) : null}
            <Label htmlFor="ticket-comment-edit-body">Comment</Label>
            <Textarea
              id="ticket-comment-edit-body"
              maxLength={40_000}
              value={editDraft.bodyMarkdown}
              onChange={(event) => {
                setEditDraft((current) => ({
                  ...current,
                  bodyMarkdown: event.target.value,
                }));
                setEditPreview(null);
              }}
            />
            <Label htmlFor="ticket-comment-edit-reason">Reason for edit</Label>
            <Input
              id="ticket-comment-edit-reason"
              maxLength={1_000}
              required
              value={editReason}
              onChange={(event) => setEditReason(event.target.value)}
            />
            <CommentAttachmentInput
              id="ticket-comment-edit-attachments"
              value={editDraft.attachmentText}
              onChange={(attachmentText) => {
                setEditDraft((current) => ({ ...current, attachmentText }));
                setEditPreview(null);
              }}
            />
            <MentionPicker
              candidates={candidates.data ?? []}
              selected={editDraft.mentionedMembershipIds}
              onChange={changeEditMention}
            />
            {editPreview ? <CommentPreview preview={editPreview} /> : null}
            <div>
              <Button
                type="button"
                variant="outline"
                disabled={pending !== null}
                onClick={() => void previewDraft(editDraft, true)}
              >
                Preview edit
              </Button>
              <Button type="submit" disabled={pending !== null}>
                {pending === "edit" ? "Saving revision…" : "Save revision"}
              </Button>
            </div>
          </form>
        ) : null}
        {history.isPending ? (
          <p aria-live="polite">Loading revision history…</p>
        ) : null}
        {history.isError ? (
          <FocusedError
            title="History unavailable"
            message={describeTicketingError(
              history.error,
              "Comment history could not be loaded.",
            )}
          />
        ) : null}
        <ol>
          {history.data?.items.map((revision) => (
            <li key={revision.revision}>
              <strong>Revision {revision.revision}</strong>
              <span>
                {revision.reason} · <TenantInstant value={revision.editedAt} />
              </span>
              <SafeMarkdown markdown={revision.bodyMarkdown} />
            </li>
          ))}
        </ol>
      </DialogContent>
    </Dialog>
  );
}

interface TicketCommentComposerProps {
  candidates: ReturnType<typeof useTicketCommentPanelState>["candidates"];
  canWritePrivate: ReturnType<
    typeof useTicketCommentPanelState
  >["canWritePrivate"];
  changeMention: ReturnType<typeof useTicketCommentPanelState>["changeMention"];
  composerMode: ReturnType<typeof useTicketCommentPanelState>["composerMode"];
  draft: ReturnType<typeof useTicketCommentPanelState>["draft"];
  error: ReturnType<typeof useTicketCommentPanelState>["error"];
  pending: ReturnType<typeof useTicketCommentPanelState>["pending"];
  preview: ReturnType<typeof useTicketCommentPanelState>["preview"];
  previewDraft: ReturnType<
    typeof createTicketCommentPanelActions
  >["previewDraft"];
  setComposerMode: ReturnType<
    typeof useTicketCommentPanelState
  >["setComposerMode"];
  setDraft: ReturnType<typeof useTicketCommentPanelState>["setDraft"];
  setPreview: ReturnType<typeof useTicketCommentPanelState>["setPreview"];
  submit: ReturnType<typeof createTicketCommentPanelActions>["submit"];
}

function TicketCommentComposer({
  candidates,
  canWritePrivate,
  changeMention,
  composerMode,
  draft,
  error,
  pending,
  preview,
  previewDraft,
  setComposerMode,
  setDraft,
  setPreview,
  submit,
}: TicketCommentComposerProps): React.JSX.Element {
  return (
    <form
      className="ticket-comment-composer"
      onSubmit={(event) => void submit(event)}
    >
      <div className="ticket-comment-composer__heading">
        <div>
          <p className="section-label">Add context</p>
          <h3>Post a Markdown comment</h3>
        </div>
        <span>HTML stays disabled</span>
      </div>
      <div role="tablist" aria-label="Comment composer mode">
        <Button
          type="button"
          role="tab"
          aria-selected={composerMode === "write"}
          variant={composerMode === "write" ? "default" : "outline"}
          size="sm"
          onClick={() => setComposerMode("write")}
        >
          Write
        </Button>
        <Button
          type="button"
          role="tab"
          aria-selected={composerMode === "preview"}
          variant={composerMode === "preview" ? "default" : "outline"}
          size="sm"
          disabled={pending !== null}
          onClick={() => void previewDraft(draft, false)}
        >
          Preview
        </Button>
      </div>
      {error ? (
        <FocusedError message={error} title="Comment not posted" />
      ) : null}
      {composerMode === "write" ? (
        <>
          <Textarea
            aria-label="Comment"
            maxLength={40_000}
            rows={5}
            value={draft.bodyMarkdown}
            onChange={(event) => {
              setDraft((current) => ({
                ...current,
                bodyMarkdown: event.target.value,
              }));
              setPreview(null);
            }}
            placeholder="Record what changed, why it matters, and the next verified step."
          />
          <CommentAttachmentInput
            value={draft.attachmentText}
            onChange={(attachmentText) => {
              setDraft((current) => ({ ...current, attachmentText }));
              setPreview(null);
            }}
          />
          <MentionPicker
            candidates={candidates.data ?? []}
            selected={draft.mentionedMembershipIds}
            onChange={changeMention}
          />
        </>
      ) : preview ? (
        <CommentPreview preview={preview} />
      ) : (
        <p>No accepted preview is available.</p>
      )}
      <div className="ticket-comment-composer__actions">
        {canWritePrivate ? (
          <label>
            <Checkbox
              checked={draft.visibility === "private"}
              onCheckedChange={(checked) => {
                setDraft((current) => ({
                  ...current,
                  visibility: checked === true ? "private" : "public",
                }));
                setPreview(null);
              }}
            />
            Private operator note
          </label>
        ) : (
          <span>
            <ShieldCheck aria-hidden="true" /> Public customer-safe comment
          </span>
        )}
        <Button type="submit" size="sm" disabled={pending !== null}>
          {pending === "create" ? "Posting comment…" : "Post comment"}
        </Button>
      </div>
    </form>
  );
}
