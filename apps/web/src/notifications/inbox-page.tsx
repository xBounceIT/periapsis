import {
  useInfiniteQuery,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { Badge } from "@periapsis/ui/components/ui/badge";
import { Button } from "@periapsis/ui/components/ui/button";
import {
  BellRing,
  BriefcaseBusiness,
  CheckCheck,
  ChevronDown,
  CircleUserRound,
  ClipboardCheck,
  ExternalLink,
  FileLock2,
  LoaderCircle,
  MailCheck,
  MailOpen,
  RefreshCw,
  ShieldX,
} from "lucide-react";
import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router";

import { FocusedError } from "../components/focused-error";
import {
  idempotencyKeyForPayload,
  type IdempotencyReference,
} from "../lib/payload-idempotency";
import { TenantInstant } from "../lib/tenant-date-time-context";
import {
  describeNotificationInboxError,
  isNotificationExpectedRevision,
  mergeNotificationInboxPages,
  NotificationInboxApiError,
  NotificationInboxProjectionError,
  notificationInboxPageLimit,
  projectNotificationInboxPage,
  projectNotificationMarkAllReadResult,
  projectNotificationReadStateResult,
  projectNotificationUnreadState,
} from "./inbox-api";
import { useNotificationInbox } from "./inbox-context";
import {
  notificationEventLabel,
  notificationResourceLabel,
  notificationResourcePath,
  type NotificationInboxItemView,
  type NotificationResourceKind,
} from "./inbox-model";

// oxlint-disable-next-line import/no-unassigned-import -- Vite extracts this page-owned stylesheet.
import "./inbox-page.css";

type PendingMutation = { itemId: string; kind: "item" } | { kind: "mark-all" };
type AccessBlock = {
  identityKey: string;
  reason: "forbidden" | "unauthorized";
};

export function NotificationInboxPage(): React.JSX.Element {
  const {
    api,
    boundary,
    clearCurrentSession,
    message,
    reloadAuthority,
    status,
  } = useNotificationInbox();
  const queryClient = useQueryClient();
  const [unreadOnly, setUnreadOnly] = useState(false);
  const [pending, setPending] = useState<PendingMutation | null>(null);
  const [problem, setProblem] = useState<string>();
  const [accessBlock, setAccessBlock] = useState<AccessBlock>();
  const boundaryToken = useRef<object>({});
  const activeMutation = useRef<AbortController | null>(null);
  const itemAttempts = useRef(new Map<string, IdempotencyReference>());
  const markAllAttempt = useRef<IdempotencyReference>({ current: null });
  const handledQueryAccessError = useRef<unknown>(undefined);
  const latestIdentity = useRef<string | undefined>(undefined);
  const cacheScope = useMemo(
    () => ["personal-notification-inbox", boundary?.key ?? status] as const,
    [boundary?.key, status],
  );
  const listQueryKey = useMemo(
    () => [...cacheScope, "list", unreadOnly] as const,
    [cacheScope, unreadOnly],
  );
  const unreadQueryKey = useMemo(
    () => [...cacheScope, "unread-count"] as const,
    [cacheScope],
  );
  const accessBlocked =
    boundary !== undefined && accessBlock?.identityKey === boundary.identityKey;
  const canLoad =
    status === "ready" && boundary !== undefined && !accessBlocked;

  const listQuery = useInfiniteQuery({
    enabled: canLoad,
    initialPageParam: undefined as string | undefined,
    queryFn: async ({ pageParam, signal }) => {
      if (!boundary) throw new NotificationInboxProjectionError();
      const request = {
        ...(pageParam === undefined ? {} : { after: pageParam }),
        limit: notificationInboxPageLimit,
        signal,
        tenantId: boundary.tenantId,
        unreadOnly,
      };
      const result = await api.list(request);
      return projectNotificationInboxPage(result, boundary, request);
    },
    queryKey: listQueryKey,
    getNextPageParam: (page) => page.nextCursor,
    retry: false,
  });
  const unreadQuery = useQuery({
    enabled: canLoad,
    queryFn: async ({ signal }) => {
      if (!boundary) throw new NotificationInboxProjectionError();
      return projectNotificationUnreadState(
        await api.countUnread({ signal, tenantId: boundary.tenantId }),
        boundary,
      );
    },
    queryKey: unreadQueryKey,
    retry: false,
  });
  const projection = useMemo(
    () =>
      boundary
        ? mergeNotificationInboxPages(
            listQuery.data?.pages ?? [],
            boundary,
            unreadOnly,
          )
        : { canonical: true, items: [] },
    [boundary, listQuery.data?.pages, unreadOnly],
  );
  const queryErrors = [listQuery.error, unreadQuery.error];
  const queryAccessError =
    queryErrors.find(isUnauthorizedError) ?? queryErrors.find(isForbiddenError);
  const queryError = queryAccessError ?? listQuery.error ?? unreadQuery.error;

  useLayoutEffect(() => {
    boundaryToken.current = {};
    activeMutation.current?.abort();
    activeMutation.current = null;
    itemAttempts.current.clear();
    markAllAttempt.current.current = null;
    handledQueryAccessError.current = undefined;
    setPending(null);
    setProblem(undefined);
    setUnreadOnly(false);

    const ownedScope = cacheScope;
    return () => {
      boundaryToken.current = {};
      activeMutation.current?.abort();
      activeMutation.current = null;
      void queryClient.cancelQueries({ queryKey: ownedScope });
      queryClient.removeQueries({ queryKey: ownedScope });
    };
  }, [boundary?.key, cacheScope, queryClient]);

  useEffect(() => {
    if (!boundary || latestIdentity.current === boundary.identityKey) return;
    latestIdentity.current = boundary.identityKey;
    setAccessBlock(undefined);
  }, [boundary]);

  useEffect(() => {
    if (listQuery.isSuccess && unreadQuery.isSuccess) {
      handledQueryAccessError.current = undefined;
    }
    if (
      !boundary ||
      !(queryError instanceof NotificationInboxApiError) ||
      (queryError.status !== 401 && queryError.status !== 403) ||
      handledQueryAccessError.current === queryError
    ) {
      return;
    }
    handledQueryAccessError.current = queryError;
    if (queryError.status === 401) {
      setAccessBlock({
        identityKey: boundary.identityKey,
        reason: "unauthorized",
      });
      clearCurrentSession();
    } else {
      setAccessBlock({
        identityKey: boundary.identityKey,
        reason: "forbidden",
      });
      reloadAuthority();
    }
  }, [
    boundary,
    clearCurrentSession,
    listQuery.isSuccess,
    queryError,
    reloadAuthority,
    unreadQuery.isSuccess,
  ]);

  if (status === "inactive") {
    return (
      <InboxBoundary
        detail="This inbox is always tenant-local. Select an active tenant before loading personal notifications."
        title="Select a tenant to view notifications"
      />
    );
  }
  if (status === "loading") return <InboxSkeleton page />;
  if (status !== "ready" || !boundary) {
    return (
      <InboxBoundary
        detail={
          message ??
          "Live authority is not ready. No personal notification request was sent."
        }
        title="Notifications are not available"
      />
    );
  }
  if (accessBlocked) {
    const forbidden = accessBlock?.reason === "forbidden";
    return (
      <InboxBoundary
        action={
          forbidden ? (
            <Button
              onClick={() => {
                handledQueryAccessError.current = undefined;
                setAccessBlock(undefined);
              }}
              type="button"
              variant="outline"
            >
              <RefreshCw aria-hidden="true" /> Recheck notifications
            </Button>
          ) : undefined
        }
        detail={
          forbidden
            ? "The inbox service rejected the current tenant authority. Authority was reloaded and further calls remain paused until you recheck."
            : "The inbox service rejected the current session. It was cleared and no further inbox call can be sent from this page."
        }
        title="Notification access changed"
      />
    );
  }

  const loading = listQuery.isPending || unreadQuery.isPending;
  const failed = queryError !== null;
  const canMutate =
    !failed &&
    projection.canonical &&
    !loading &&
    pending === null &&
    boundary.csrfToken.trim() !== "";
  const canMarkAllRead =
    canMutate &&
    unreadQuery.data !== undefined &&
    unreadQuery.data.count > 0 &&
    isNotificationExpectedRevision(unreadQuery.data.inboxRevision, true);

  const invalidateInbox = async (): Promise<void> => {
    await Promise.all([
      queryClient.invalidateQueries({
        exact: true,
        queryKey: [...cacheScope, "list", false],
      }),
      queryClient.invalidateQueries({
        exact: true,
        queryKey: [...cacheScope, "list", true],
      }),
      queryClient.invalidateQueries({
        exact: true,
        queryKey: unreadQueryKey,
      }),
    ]);
  };

  const handleMutationError = async (
    error: unknown,
    token: object,
    controller: AbortController,
  ): Promise<void> => {
    if (!ownsMutation(token, controller) || isAbortError(error)) return;
    if (error instanceof NotificationInboxApiError && error.status === 401) {
      setAccessBlock({
        identityKey: boundary.identityKey,
        reason: "unauthorized",
      });
      clearCurrentSession();
      return;
    }
    if (error instanceof NotificationInboxApiError && error.status === 403) {
      setAccessBlock({
        identityKey: boundary.identityKey,
        reason: "forbidden",
      });
      reloadAuthority();
      return;
    }
    if (
      error instanceof NotificationInboxApiError &&
      (error.status === 409 || error.status === 412 || error.status === 428)
    ) {
      await invalidateInbox();
      if (ownsMutation(token, controller)) {
        setProblem(
          "Notification state changed elsewhere. The latest inbox was reloaded; review it before retrying.",
        );
      }
      return;
    }
    setProblem(
      describeNotificationInboxError(
        error,
        "The notification state could not be updated. Retrying the same action will reuse its idempotency key.",
      ),
    );
  };

  const setReadState = async (
    item: NotificationInboxItemView,
    read: boolean,
  ): Promise<void> => {
    if (
      !canMutate ||
      activeMutation.current ||
      !isNotificationExpectedRevision(item.revision)
    ) {
      return;
    }
    let attempt = itemAttempts.current.get(item.id);
    if (!attempt) {
      attempt = { current: null };
      itemAttempts.current.set(item.id, attempt);
    }
    const payload = {
      audience: item.audience,
      expectedRevision: item.revision,
      itemId: item.id,
      operation: "notification-inbox.set-read-state",
      read,
      sessionId: boundary.sessionId,
      tenantId: boundary.tenantId,
    };
    const controller = new AbortController();
    const token = boundaryToken.current;
    activeMutation.current = controller;
    setPending({ itemId: item.id, kind: "item" });
    setProblem(undefined);
    try {
      const request = {
        csrfToken: boundary.csrfToken,
        expectedRevision: item.revision,
        idempotencyKey: idempotencyKeyForPayload(attempt, payload),
        itemId: item.id,
        read,
        signal: controller.signal,
        tenantId: boundary.tenantId,
      };
      projectNotificationReadStateResult(
        await api.setReadState(request),
        boundary,
        { ...request, audience: item.audience },
      );
      if (!ownsMutation(token, controller)) return;
      itemAttempts.current.delete(item.id);
      await invalidateInbox();
    } catch (error) {
      await handleMutationError(error, token, controller);
    } finally {
      if (ownsMutation(token, controller)) {
        activeMutation.current = null;
        setPending(null);
      }
    }
  };

  const markAllRead = async (): Promise<void> => {
    const unread = unreadQuery.data;
    if (!canMarkAllRead || activeMutation.current || !unread) {
      return;
    }
    const payload = {
      expectedRevision: unread.inboxRevision,
      operation: "notification-inbox.mark-all-read",
      sessionId: boundary.sessionId,
      tenantId: boundary.tenantId,
    };
    const controller = new AbortController();
    const token = boundaryToken.current;
    activeMutation.current = controller;
    setPending({ kind: "mark-all" });
    setProblem(undefined);
    try {
      const request = {
        csrfToken: boundary.csrfToken,
        expectedRevision: unread.inboxRevision,
        idempotencyKey: idempotencyKeyForPayload(
          markAllAttempt.current,
          payload,
        ),
        signal: controller.signal,
        tenantId: boundary.tenantId,
      };
      projectNotificationMarkAllReadResult(
        await api.markAllRead(request),
        boundary,
        request.expectedRevision,
      );
      if (!ownsMutation(token, controller)) return;
      markAllAttempt.current.current = null;
      await invalidateInbox();
    } catch (error) {
      await handleMutationError(error, token, controller);
    } finally {
      if (ownsMutation(token, controller)) {
        activeMutation.current = null;
        setPending(null);
      }
    }
  };

  const ownsMutation = (token: object, controller: AbortController): boolean =>
    boundaryToken.current === token &&
    activeMutation.current === controller &&
    !controller.signal.aborted;

  return (
    <main className="content notification-inbox-page">
      <section
        aria-labelledby="notification-inbox-title"
        className="page-heading notification-inbox-heading"
      >
        <div>
          <p className="section-label">Personal signal queue</p>
          <h1 id="notification-inbox-title">Notifications</h1>
          <p>
            Newest-first updates for your personal identity. Every page and
            state change is rechecked against the active tenant and session.
          </p>
        </div>
        <div
          aria-label="Unread notification count"
          aria-live="polite"
          className="notification-inbox-count"
        >
          <span>Unread</span>
          <strong>{unreadQuery.data?.count ?? "—"}</strong>
          <small>personal inbox</small>
        </div>
      </section>

      <section
        aria-labelledby="notification-inbox-queue-title"
        className="notification-inbox-shell"
      >
        <header className="notification-inbox-toolbar">
          <div>
            <span className="notification-inbox-signal" aria-hidden="true" />
            <span>
              <h2 id="notification-inbox-queue-title">Signal queue</h2>
              <small>Strict UUIDv7 order · older pages on demand</small>
            </span>
          </div>
          <div className="notification-inbox-actions">
            <label className="notification-inbox-filter">
              <input
                checked={unreadOnly}
                disabled={failed || loading || pending !== null}
                onChange={(event) => setUnreadOnly(event.currentTarget.checked)}
                type="checkbox"
              />
              Unread only
            </label>
            <Button
              disabled={!canMarkAllRead}
              onClick={() => void markAllRead()}
              size="sm"
              type="button"
              variant="outline"
            >
              {pending?.kind === "mark-all" ? (
                <LoaderCircle aria-hidden="true" className="inbox-spin" />
              ) : (
                <CheckCheck aria-hidden="true" />
              )}
              {pending?.kind === "mark-all" ? "Marking…" : "Mark all read"}
            </Button>
          </div>
        </header>

        {problem ? (
          <p className="notification-inbox-problem" role="alert">
            {problem}
          </p>
        ) : null}
        {loading ? <InboxSkeleton /> : null}
        {failed ? (
          <div className="notification-inbox-error">
            <FocusedError
              message={describeNotificationInboxError(
                queryError,
                "The current authorized notification snapshot could not be loaded.",
              )}
              title="Notification inbox unavailable"
            />
            <Button
              disabled={listQuery.isFetching || unreadQuery.isFetching}
              onClick={() => {
                void listQuery.refetch();
                void unreadQuery.refetch();
              }}
              size="sm"
              type="button"
              variant="outline"
            >
              <RefreshCw aria-hidden="true" /> Retry inbox
            </Button>
          </div>
        ) : null}
        {!projection.canonical ? (
          <FocusedError
            message="A duplicate, non-monotonic, or cross-coordinate notification page was rejected. No ambiguous item was rendered."
            title="Notification projection rejected"
          />
        ) : null}
        {!loading &&
        !failed &&
        projection.canonical &&
        projection.items.length === 0 ? (
          <div className="notification-inbox-empty">
            <MailCheck aria-hidden="true" />
            <h3>
              {unreadOnly ? "You are all caught up" : "No notifications yet"}
            </h3>
            <p>
              {unreadOnly
                ? "There are no unread updates in this personal tenant inbox."
                : "Authorized Alert, Case, Task, Evidence, and Contact updates will appear here."}
            </p>
          </div>
        ) : null}
        {!loading &&
        !failed &&
        projection.canonical &&
        projection.items.length > 0 ? (
          <ol
            aria-label="Personal notifications"
            className="notification-inbox-list"
          >
            {projection.items.map((item) => (
              <NotificationItem
                disabled={
                  !canMutate || !isNotificationExpectedRevision(item.revision)
                }
                item={item}
                key={item.id}
                onSetReadState={(read) => void setReadState(item, read)}
                pending={pending?.kind === "item" && pending.itemId === item.id}
              />
            ))}
          </ol>
        ) : null}

        {!failed && projection.canonical && listQuery.hasNextPage ? (
          <Button
            disabled={listQuery.isFetchingNextPage || pending !== null}
            onClick={() => void listQuery.fetchNextPage()}
            type="button"
            variant="outline"
          >
            <ChevronDown aria-hidden="true" />
            {listQuery.isFetchingNextPage
              ? "Loading older notifications…"
              : "Load older notifications"}
          </Button>
        ) : null}
      </section>
    </main>
  );
}

function NotificationItem({
  disabled,
  item,
  onSetReadState,
  pending,
}: {
  disabled: boolean;
  item: NotificationInboxItemView;
  onSetReadState: (read: boolean) => void;
  pending: boolean;
}): React.JSX.Element {
  const read = item.readAt !== null;
  const path = notificationResourcePath(item);
  const ResourceIcon = resourceIcons[item.resourceKind];
  return (
    <li className={read ? undefined : "notification-inbox-item--unread"}>
      <span className="notification-inbox-item__icon" aria-hidden="true">
        <ResourceIcon />
      </span>
      <article>
        <header>
          <div>
            <span className="notification-inbox-item__eyebrow">
              {notificationEventLabel(item.eventType)}
            </span>
            <h3>{item.title}</h3>
          </div>
          <Badge variant={read ? "outline" : "secondary"}>
            {read ? "Read" : "Unread"}
          </Badge>
        </header>
        {item.summary ? <p>{item.summary}</p> : null}
        <footer>
          <span>
            {notificationResourceLabel(item.resourceKind)} · v
            {item.resourceVersion} · <TenantInstant value={item.occurredAt} />
          </span>
          <span className="notification-inbox-item__actions">
            {path ? (
              <Button asChild size="sm" variant="ghost">
                <Link to={path}>
                  Open {notificationResourceLabel(item.resourceKind)}
                  <ExternalLink aria-hidden="true" />
                </Link>
              </Button>
            ) : null}
            <Button
              aria-label={`Mark ${item.title} as ${read ? "unread" : "read"}`}
              disabled={disabled}
              onClick={() => onSetReadState(!read)}
              size="sm"
              type="button"
              variant="outline"
            >
              {pending ? (
                <LoaderCircle aria-hidden="true" className="inbox-spin" />
              ) : read ? (
                <MailOpen aria-hidden="true" />
              ) : (
                <MailCheck aria-hidden="true" />
              )}
              {pending ? "Saving…" : read ? "Mark unread" : "Mark read"}
            </Button>
          </span>
        </footer>
      </article>
    </li>
  );
}

function InboxBoundary({
  action,
  detail,
  title,
}: {
  action?: React.ReactNode;
  detail: string;
  title: string;
}): React.JSX.Element {
  return (
    <main className="content content--narrow notification-inbox-boundary">
      <section
        aria-labelledby="notification-inbox-boundary-title"
        className="page-heading"
      >
        <p className="section-label">Personal signal queue</p>
        <h1 id="notification-inbox-boundary-title">{title}</h1>
        <p>{detail}</p>
      </section>
      <div className="notification-inbox-boundary__card">
        <ShieldX aria-hidden="true" />
        <strong>Deny-by-default boundary</strong>
        <p>UI visibility never authorizes access to a personal inbox.</p>
        {action}
      </div>
    </main>
  );
}

function InboxSkeleton({
  page = false,
}: {
  page?: boolean;
}): React.JSX.Element {
  return (
    <div
      aria-busy="true"
      aria-label="Loading notifications"
      className={`notification-inbox-skeleton${page ? " notification-inbox-skeleton--page" : ""}`}
    >
      {Array.from({ length: page ? 6 : 4 }, (_, index) => (
        <span key={index} />
      ))}
    </div>
  );
}

const resourceIcons = {
  alert: BellRing,
  case: BriefcaseBusiness,
  contact: CircleUserRound,
  evidence: FileLock2,
  task: ClipboardCheck,
} as const satisfies Record<NotificationResourceKind, typeof BellRing>;

function isAbortError(error: unknown): boolean {
  return error instanceof DOMException && error.name === "AbortError";
}

function isUnauthorizedError(error: unknown): boolean {
  return error instanceof NotificationInboxApiError && error.status === 401;
}

function isForbiddenError(error: unknown): boolean {
  return error instanceof NotificationInboxApiError && error.status === 403;
}
