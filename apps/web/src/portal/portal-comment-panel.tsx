import { Button } from "@periapsis/ui/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@periapsis/ui/components/ui/dialog";
import { Label } from "@periapsis/ui/components/ui/label";
import { Textarea } from "@periapsis/ui/components/ui/textarea";
import {
  useInfiniteQuery,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { History, Paperclip, Pencil, Send } from "lucide-react";
import { useLayoutEffect, useRef, useState, type FormEvent } from "react";

import { useSession } from "../auth/session-context";
import { useTenantAuthority } from "../auth/tenant-authority-context";
import { FocusedError } from "../components/focused-error";
import {
  ContactApiError,
  type ContactPortalApi,
  type PortalComment,
  type PortalCommentPreview,
} from "../contacts/contact-api";
import {
  hasGoTrimSpaceAtEdge,
  hasUnpairedSurrogate,
} from "../lib/canonical-display-name";
import {
  idempotencyKeyForPayload,
  type IdempotencyReference,
} from "../lib/payload-idempotency";
import { hasForbiddenCommentMarkdownCharacters } from "../lib/text-validation";
import { SafeMarkdown } from "../ticketing/safe-markdown";

type PortalKind = "alert" | "case";

function usePortalCommentPanelState({
  api,
  canComment,
  csrfToken,
  kind,
  resourceId,
  tenantId,
}: {
  api: ContactPortalApi;
  canComment: boolean;
  csrfToken: string;
  kind: PortalKind;
  resourceId: string;
  tenantId: string;
}) {
  const { session } = useSession();
  const authority = useTenantAuthority();
  const client = useQueryClient();
  const [bodyMarkdown, setBodyMarkdown] = useState("");
  const [attachmentText, setAttachmentText] = useState("");
  const [mode, setMode] = useState<"preview" | "write">("write");
  const [preview, setPreview] = useState<PortalCommentPreview | null>(null);
  const [selected, setSelected] = useState<PortalComment | null>(null);
  const [dialogMode, setDialogMode] = useState<"edit" | "history" | null>(null);
  const [editBody, setEditBody] = useState("");
  const [editAttachmentText, setEditAttachmentText] = useState("");
  const [editPreview, setEditPreview] = useState<PortalCommentPreview | null>(
    null,
  );
  const [pending, setPending] = useState<"create" | "edit" | "preview" | null>(
    null,
  );
  const [error, setError] = useState<string | null>(null);
  const [editError, setEditError] = useState<string | null>(null);
  const commentAttempt = useRef<IdempotencyReference["current"]>(null);
  const editAttempt = useRef<IdempotencyReference["current"]>(null);
  const controllerRef = useRef<AbortController | null>(null);
  const boundary = JSON.stringify([
    authority.pairKey,
    authority.revision,
    authority.authority?.evaluatedAt ?? null,
    session.id,
    session.activeTenantId,
    csrfToken,
    tenantId,
    kind,
    resourceId,
    canComment,
  ]);
  const boundaryRef = useRef(boundary);
  useLayoutEffect(() => {
    boundaryRef.current = boundary;
    controllerRef.current?.abort();
    controllerRef.current = null;
    commentAttempt.current = null;
    editAttempt.current = null;
    setPending(null);
    setError(null);
    setEditError(null);
    setPreview(null);
    setEditPreview(null);
    setSelected(null);
    setDialogMode(null);
    setBodyMarkdown("");
    setAttachmentText("");
    setMode("write");
    setEditBody("");
    setEditAttachmentText("");
    return () => controllerRef.current?.abort();
  }, [boundary]);
  const comments = useInfiniteQuery({
    enabled: canComment,
    queryKey: ["customer-portal-comments", boundary],
    initialPageParam: undefined as string | undefined,
    queryFn: ({ pageParam, signal }) =>
      api.listPortalComments({
        ...(pageParam ? { after: pageParam } : {}),
        kind,
        resourceId,
        signal,
        tenantId,
      }),
    getNextPageParam: (lastPage) => lastPage.nextCursor,
  });
  const history = useQuery({
    enabled: canComment && selected !== null && dialogMode !== null,
    queryKey: ["customer-portal-comment-history", boundary, selected?.id],
    queryFn: ({ signal }) =>
      api.listPortalCommentRevisions({
        commentId: selected!.id,
        kind,
        resourceId,
        signal,
        tenantId,
      }),
  });
  const items = comments.data?.pages.flatMap((page) => page.items) ?? [];
  return {
    api,
    canComment,
    csrfToken,
    kind,
    resourceId,
    tenantId,
    session,
    authority,
    client,
    bodyMarkdown,
    setBodyMarkdown,
    attachmentText,
    setAttachmentText,
    mode,
    setMode,
    preview,
    setPreview,
    selected,
    setSelected,
    dialogMode,
    setDialogMode,
    editBody,
    setEditBody,
    editAttachmentText,
    setEditAttachmentText,
    editPreview,
    setEditPreview,
    pending,
    setPending,
    error,
    setError,
    editError,
    setEditError,
    commentAttempt,
    editAttempt,
    controllerRef,
    boundary,
    boundaryRef,
    comments,
    history,
    items,
  };
}

function createPortalCommentPanelActions({
  api,
  canComment,
  csrfToken,
  kind,
  resourceId,
  tenantId,
  client,
  bodyMarkdown,
  setBodyMarkdown,
  attachmentText,
  setAttachmentText,
  setMode,
  setPreview,
  selected,
  setSelected,
  setDialogMode,
  editBody,
  setEditBody,
  editAttachmentText,
  setEditAttachmentText,
  setEditPreview,
  setPending,
  setError,
  setEditError,
  commentAttempt,
  editAttempt,
  controllerRef,
  boundary,
  boundaryRef,
  comments,
  history,
}: ReturnType<typeof usePortalCommentPanelState>) {
  function beginRequest(): {
    controller: AbortController;
    requestedBoundary: string;
  } {
    controllerRef.current?.abort();
    const controller = new AbortController();
    controllerRef.current = controller;
    return { controller, requestedBoundary: boundary };
  }
  function current(
    controller: AbortController,
    requestedBoundary: string,
  ): boolean {
    return (
      !controller.signal.aborted && boundaryRef.current === requestedBoundary
    );
  }
  async function requestPreview(editing: boolean): Promise<void> {
    const draft = portalDraft(
      editing ? editBody : bodyMarkdown,
      editing ? editAttachmentText : attachmentText,
    );
    if (!draft.ok) {
      if (editing) setEditError(draft.error);
      else setError(draft.error);
      return;
    }
    const { controller, requestedBoundary } = beginRequest();
    setPending("preview");
    try {
      const result = await api.previewPortalComment({
        ...draft.value,
        csrfToken,
        kind,
        resourceId,
        signal: controller.signal,
        tenantId,
      });
      if (!current(controller, requestedBoundary)) return;
      if (editing) setEditPreview(result);
      else {
        setPreview(result);
        setMode("preview");
      }
    } catch (caught) {
      if (!current(controller, requestedBoundary)) return;
      const message = portalError(caught);
      if (editing) setEditError(message);
      else setError(message);
    } finally {
      if (current(controller, requestedBoundary)) setPending(null);
    }
  }
  async function create(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const draft = portalDraft(bodyMarkdown, attachmentText);
    if (!draft.ok) {
      setError(draft.error);
      return;
    }
    const idempotencyKey = idempotencyKeyForPayload(commentAttempt, {
      ...draft.value,
      kind,
      operation: "portal.comment.create",
      resourceId,
      tenantId,
    });
    const { controller, requestedBoundary } = beginRequest();
    setError(null);
    setPending("create");
    try {
      await api.createPortalComment({
        ...draft.value,
        csrfToken,
        idempotencyKey,
        kind,
        resourceId,
        signal: controller.signal,
        tenantId,
      });
      if (!current(controller, requestedBoundary)) return;
      commentAttempt.current = null;
      setBodyMarkdown("");
      setAttachmentText("");
      setPreview(null);
      setMode("write");
      await comments.refetch();
      void client.invalidateQueries({
        queryKey: ["customer-portal-activities", tenantId, kind, resourceId],
      });
    } catch (caught) {
      if (current(controller, requestedBoundary)) setError(portalError(caught));
    } finally {
      if (current(controller, requestedBoundary)) setPending(null);
    }
  }
  async function edit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (!selected || !isPortalCommentEditable(selected, canComment)) {
      setEditError("This comment is no longer editable by its author.");
      return;
    }
    const draft = portalDraft(editBody, editAttachmentText);
    if (!draft.ok) {
      setEditError(draft.error);
      return;
    }
    const etag = `"comment-r${selected.revision}"`;
    const idempotencyKey = idempotencyKeyForPayload(editAttempt, {
      ...draft.value,
      commentId: selected.id,
      etag,
      kind,
      operation: "portal.comment.edit",
      resourceId,
      tenantId,
    });
    const { controller, requestedBoundary } = beginRequest();
    setEditError(null);
    setPending("edit");
    try {
      await api.editPortalComment({
        ...draft.value,
        commentId: selected.id,
        csrfToken,
        etag,
        idempotencyKey,
        kind,
        resourceId,
        signal: controller.signal,
        tenantId,
      });
      if (!current(controller, requestedBoundary)) return;
      editAttempt.current = null;
      await Promise.all([comments.refetch(), history.refetch()]);
      if (!current(controller, requestedBoundary)) return;
      setDialogMode("history");
      setEditPreview(null);
    } catch (caught) {
      if (!current(controller, requestedBoundary)) return;
      if (
        caught instanceof ContactApiError &&
        (caught.status === 412 || caught.status === 428)
      ) {
        editAttempt.current = null;
        const [freshComments] = await Promise.all([
          comments.refetch(),
          history.refetch(),
        ]);
        if (!current(controller, requestedBoundary)) return;
        const latest = freshComments.data?.pages
          .flatMap((page) => page.items)
          .find((comment) => comment.id === selected.id);
        if (latest) {
          setSelected(latest);
          setEditBody(latest.bodyMarkdown);
          setEditAttachmentText(
            latest.attachments.map((item) => item.id).join("\n"),
          );
          setEditPreview(null);
        }
        setEditError(
          "This comment changed on the server. Review the latest revision before retrying.",
        );
      } else {
        setEditError(portalError(caught));
      }
    } finally {
      if (current(controller, requestedBoundary)) setPending(null);
    }
  }
  function openDialog(
    comment: PortalComment,
    nextMode: "edit" | "history",
  ): void {
    setSelected(comment);
    setDialogMode(nextMode);
    setEditBody(comment.bodyMarkdown);
    setEditAttachmentText(
      comment.attachments.map((item) => item.id).join("\n"),
    );
    setEditPreview(null);
    setEditError(null);
    editAttempt.current = null;
  }
  return { beginRequest, current, requestPreview, create, edit, openDialog };
}

export function PortalCommentPanel(props: {
  api: ContactPortalApi;
  canComment: boolean;
  csrfToken: string;
  kind: PortalKind;
  resourceId: string;
  tenantId: string;
}): React.JSX.Element | null {
  const state = usePortalCommentPanelState(props);
  const {
    canComment,
    bodyMarkdown,
    setBodyMarkdown,
    attachmentText,
    setAttachmentText,
    mode,
    setMode,
    preview,
    setPreview,
    selected,
    setSelected,
    dialogMode,
    setDialogMode,
    editBody,
    setEditBody,
    editAttachmentText,
    setEditAttachmentText,
    editPreview,
    setEditPreview,
    pending,
    error,
    editError,
    controllerRef,
    comments,
    history,
    items,
  } = state;
  if (!canComment) return null;
  const { requestPreview, create, edit, openDialog } =
    createPortalCommentPanelActions(state);
  return (
    <section
      className="portal-comments"
      aria-labelledby="portal-comments-title"
    >
      <h3 id="portal-comments-title">Public conversation</h3>
      <p>
        Every message is public to linked customer contacts. Mentions and
        private attachments are unavailable.
      </p>
      {comments.isPending ? (
        <p aria-live="polite">Loading public comments…</p>
      ) : null}
      {comments.isError ? (
        <FocusedError
          title="Comments unavailable"
          message={portalError(comments.error)}
        />
      ) : null}
      {!comments.isPending && items.length === 0 ? (
        <p>No public comments.</p>
      ) : null}
      <PortalCommentInventory
        canComment={canComment}
        items={items}
        openDialog={openDialog}
      />
      {comments.hasNextPage ? (
        <Button
          type="button"
          size="sm"
          variant="outline"
          onClick={() => void comments.fetchNextPage()}
        >
          Load earlier comments
        </Button>
      ) : null}
      {canComment ? (
        <PortalCommentComposer
          attachmentText={attachmentText}
          bodyMarkdown={bodyMarkdown}
          create={create}
          error={error}
          mode={mode}
          pending={pending}
          preview={preview}
          requestPreview={requestPreview}
          setAttachmentText={setAttachmentText}
          setBodyMarkdown={setBodyMarkdown}
          setMode={setMode}
          setPreview={setPreview}
        />
      ) : null}
      <PortalCommentDialog
        controllerRef={controllerRef}
        dialogMode={dialogMode}
        edit={edit}
        editAttachmentText={editAttachmentText}
        editBody={editBody}
        editError={editError}
        editPreview={editPreview}
        history={history}
        pending={pending}
        requestPreview={requestPreview}
        selected={selected}
        setDialogMode={setDialogMode}
        setEditAttachmentText={setEditAttachmentText}
        setEditBody={setEditBody}
        setEditPreview={setEditPreview}
        setSelected={setSelected}
      />
    </section>
  );
}

function portalDraft(
  body: string,
  attachmentText: string,
):
  | { ok: true; value: { bodyMarkdown: string; attachmentIds?: string[] } }
  | { ok: false; error: string } {
  const bodyMarkdown = body;
  if (bodyMarkdown.length === 0)
    return { ok: false, error: "Write a public comment before continuing." };
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
  const parsed = parseAttachmentIds(attachmentText);
  if (!parsed.ok) return { ok: false, error: parsed.error };
  return {
    ok: true,
    value: {
      bodyMarkdown,
      ...(parsed.ids.length ? { attachmentIds: parsed.ids } : {}),
    },
  };
}

function isPortalCommentEditable(
  comment: PortalComment,
  canComment: boolean,
): boolean {
  return (
    canComment &&
    comment.canEdit &&
    comment.origin === "customer_portal" &&
    comment.author.audience === "customer" &&
    Date.parse(comment.editableUntil) > Date.now()
  );
}

function parseAttachmentIds(
  value: string,
): { ok: true; ids: string[] } | { ok: false; error: string } {
  const ids = value
    .split(/[\s,]+/u)
    .map((item) => item.trim())
    .filter(Boolean);
  if (ids.length > 20)
    return { ok: false, error: "Select at most 20 public attachment IDs." };
  if (new Set(ids).size !== ids.length)
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

function PortalAttachmentIds({
  id = "portal-comment-attachments",
  onChange,
  value,
}: {
  id?: string;
  onChange: (value: string) => void;
  value: string;
}): React.JSX.Element {
  return (
    <div>
      <Label htmlFor={id}>Public attachment IDs</Label>
      <Textarea
        id={id}
        rows={2}
        value={value}
        onChange={(event) => onChange(event.target.value)}
      />
      <small>
        <Paperclip aria-hidden="true" /> The server rechecks the same ticket and
        public visibility.
      </small>
    </div>
  );
}

function PortalPreview({
  preview,
}: {
  preview: PortalCommentPreview;
}): React.JSX.Element {
  return (
    <section aria-label="Accepted public comment preview">
      <SafeMarkdown markdown={preview.bodyMarkdown} />
      {preview.attachments.length ? (
        <p>{preview.attachments.length} public attachment(s) accepted.</p>
      ) : null}
    </section>
  );
}

function portalError(value: unknown): string {
  return value instanceof Error
    ? value.message.slice(0, 320)
    : "The public comment operation could not be completed.";
}

function formatDate(value: string): string {
  return portalCommentDateFormatter.format(new Date(value));
}

const portalCommentDateFormatter = new Intl.DateTimeFormat(undefined, {
  dateStyle: "medium",
  timeStyle: "short",
});

interface PortalCommentDialogProps {
  controllerRef: ReturnType<typeof usePortalCommentPanelState>["controllerRef"];
  dialogMode: ReturnType<typeof usePortalCommentPanelState>["dialogMode"];
  edit: ReturnType<typeof createPortalCommentPanelActions>["edit"];
  editAttachmentText: ReturnType<
    typeof usePortalCommentPanelState
  >["editAttachmentText"];
  editBody: ReturnType<typeof usePortalCommentPanelState>["editBody"];
  editError: ReturnType<typeof usePortalCommentPanelState>["editError"];
  editPreview: ReturnType<typeof usePortalCommentPanelState>["editPreview"];
  history: ReturnType<typeof usePortalCommentPanelState>["history"];
  pending: ReturnType<typeof usePortalCommentPanelState>["pending"];
  requestPreview: ReturnType<
    typeof createPortalCommentPanelActions
  >["requestPreview"];
  selected: ReturnType<typeof usePortalCommentPanelState>["selected"];
  setDialogMode: ReturnType<typeof usePortalCommentPanelState>["setDialogMode"];
  setEditAttachmentText: ReturnType<
    typeof usePortalCommentPanelState
  >["setEditAttachmentText"];
  setEditBody: ReturnType<typeof usePortalCommentPanelState>["setEditBody"];
  setEditPreview: ReturnType<
    typeof usePortalCommentPanelState
  >["setEditPreview"];
  setSelected: ReturnType<typeof usePortalCommentPanelState>["setSelected"];
}

function PortalCommentDialog({
  controllerRef,
  dialogMode,
  edit,
  editAttachmentText,
  editBody,
  editError,
  editPreview,
  history,
  pending,
  requestPreview,
  selected,
  setDialogMode,
  setEditAttachmentText,
  setEditBody,
  setEditPreview,
  setSelected,
}: PortalCommentDialogProps): React.JSX.Element {
  return (
    <Dialog
      open={selected !== null && dialogMode !== null}
      onOpenChange={(open) => {
        if (!open) {
          controllerRef.current?.abort();
          setSelected(null);
          setDialogMode(null);
        }
      }}
    >
      <DialogContent>
        <DialogHeader>
          <DialogTitle>
            {dialogMode === "edit"
              ? "Correct your public comment"
              : "Public comment history"}
          </DialogTitle>
          <DialogDescription>
            Corrections append immutable public revisions. Visibility and
            mentions cannot be changed.
          </DialogDescription>
        </DialogHeader>
        {dialogMode === "edit" ? (
          <form onSubmit={(event) => void edit(event)}>
            {editError ? (
              <FocusedError title="Comment not edited" message={editError} />
            ) : null}
            <Label htmlFor="portal-comment-edit">Comment</Label>
            <Textarea
              id="portal-comment-edit"
              maxLength={40_000}
              value={editBody}
              onChange={(event) => {
                setEditBody(event.target.value);
                setEditPreview(null);
              }}
            />
            <PortalAttachmentIds
              id="portal-comment-edit-attachments"
              value={editAttachmentText}
              onChange={(value) => {
                setEditAttachmentText(value);
                setEditPreview(null);
              }}
            />
            {editPreview ? <PortalPreview preview={editPreview} /> : null}
            <Button
              type="button"
              variant="outline"
              disabled={pending !== null}
              onClick={() => void requestPreview(true)}
            >
              Preview correction
            </Button>
            <Button type="submit" disabled={pending !== null}>
              {pending === "edit" ? "Saving correction…" : "Save correction"}
            </Button>
          </form>
        ) : null}
        {history.isPending ? (
          <p aria-live="polite">Loading public history…</p>
        ) : null}
        {history.isError ? (
          <FocusedError
            title="History unavailable"
            message={portalError(history.error)}
          />
        ) : null}
        <ol>
          {history.data?.items.map((revision) => (
            <li key={revision.revision}>
              <strong>Revision {revision.revision}</strong>
              <time dateTime={revision.editedAt}>
                {formatDate(revision.editedAt)}
              </time>
              <SafeMarkdown markdown={revision.bodyMarkdown} />
            </li>
          ))}
        </ol>
      </DialogContent>
    </Dialog>
  );
}

interface PortalCommentInventoryProps {
  canComment: ReturnType<typeof usePortalCommentPanelState>["canComment"];
  items: ReturnType<typeof usePortalCommentPanelState>["items"];
  openDialog: ReturnType<typeof createPortalCommentPanelActions>["openDialog"];
}

function PortalCommentInventory({
  canComment,
  items,
  openDialog,
}: PortalCommentInventoryProps): React.JSX.Element {
  return (
    <ol className="portal-comment-list">
      {items.map((comment) => (
        <li key={comment.id}>
          <header>
            <strong>{comment.author.displayName}</strong>
            <span>{comment.origin}</span>
            <time dateTime={comment.createdAt}>
              {formatDate(comment.createdAt)}
            </time>
          </header>
          <SafeMarkdown markdown={comment.bodyMarkdown} />
          {comment.attachments.length ? (
            <ul aria-label="Comment attachments">
              {comment.attachments.map((attachment) => (
                <li key={attachment.id}>{attachment.originalFilename}</li>
              ))}
            </ul>
          ) : null}
          <Button
            type="button"
            size="sm"
            variant="ghost"
            onClick={() => openDialog(comment, "history")}
          >
            <History aria-hidden="true" /> History
          </Button>
          {isPortalCommentEditable(comment, canComment) ? (
            <Button
              type="button"
              size="sm"
              variant="outline"
              onClick={() => openDialog(comment, "edit")}
            >
              <Pencil aria-hidden="true" /> Edit
            </Button>
          ) : null}
        </li>
      ))}
    </ol>
  );
}

interface PortalCommentComposerProps {
  attachmentText: ReturnType<
    typeof usePortalCommentPanelState
  >["attachmentText"];
  bodyMarkdown: ReturnType<typeof usePortalCommentPanelState>["bodyMarkdown"];
  create: ReturnType<typeof createPortalCommentPanelActions>["create"];
  error: ReturnType<typeof usePortalCommentPanelState>["error"];
  mode: ReturnType<typeof usePortalCommentPanelState>["mode"];
  pending: ReturnType<typeof usePortalCommentPanelState>["pending"];
  preview: ReturnType<typeof usePortalCommentPanelState>["preview"];
  requestPreview: ReturnType<
    typeof createPortalCommentPanelActions
  >["requestPreview"];
  setAttachmentText: ReturnType<
    typeof usePortalCommentPanelState
  >["setAttachmentText"];
  setBodyMarkdown: ReturnType<
    typeof usePortalCommentPanelState
  >["setBodyMarkdown"];
  setMode: ReturnType<typeof usePortalCommentPanelState>["setMode"];
  setPreview: ReturnType<typeof usePortalCommentPanelState>["setPreview"];
}

function PortalCommentComposer({
  attachmentText,
  bodyMarkdown,
  create,
  error,
  mode,
  pending,
  preview,
  requestPreview,
  setAttachmentText,
  setBodyMarkdown,
  setMode,
  setPreview,
}: PortalCommentComposerProps): React.JSX.Element {
  return (
    <form
      className="portal-comment-form"
      onSubmit={(event) => void create(event)}
    >
      <div role="tablist" aria-label="Public comment composer mode">
        <Button
          type="button"
          role="tab"
          aria-selected={mode === "write"}
          onClick={() => setMode("write")}
        >
          Write
        </Button>
        <Button
          type="button"
          role="tab"
          aria-selected={mode === "preview"}
          disabled={pending !== null}
          onClick={() => void requestPreview(false)}
        >
          Preview
        </Button>
      </div>
      {error ? (
        <FocusedError title="Comment was not sent" message={error} />
      ) : null}
      {mode === "write" ? (
        <>
          <Label htmlFor="portal-comment">Add a public comment</Label>
          <Textarea
            id="portal-comment"
            maxLength={40_000}
            required
            value={bodyMarkdown}
            onChange={(event) => {
              setBodyMarkdown(event.currentTarget.value);
              setPreview(null);
            }}
          />
          <PortalAttachmentIds
            value={attachmentText}
            onChange={(value) => {
              setAttachmentText(value);
              setPreview(null);
            }}
          />
        </>
      ) : preview ? (
        <PortalPreview preview={preview} />
      ) : (
        <p>No accepted preview is available.</p>
      )}
      <Button
        type="submit"
        disabled={pending !== null || bodyMarkdown.length === 0}
      >
        <Send aria-hidden="true" />{" "}
        {pending === "create" ? "Sending…" : "Send public comment"}
      </Button>
    </form>
  );
}
