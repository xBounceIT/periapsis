import { Button } from "@periapsis/ui/components/ui/button";
import { Input } from "@periapsis/ui/components/ui/input";
import { Label } from "@periapsis/ui/components/ui/label";
import { RefreshCw, Trash2, UserPlus, UsersRound } from "lucide-react";
import {
  useEffect,
  useId,
  useLayoutEffect,
  useRef,
  useState,
  type FormEvent,
} from "react";

import {
  idempotencyKeyForPayload,
  type IdempotencyReference,
} from "../lib/payload-idempotency";
import { TenantInstant } from "../lib/tenant-date-time-context";
import type { TicketKind } from "../lib/ticketing-api";
import {
  TicketWatcherApiError,
  watcherUuidV7Pattern,
  type TicketWatcherApi,
  type VersionedTicketWatcherPage,
} from "./ticket-watcher-api";

// oxlint-disable-next-line import/no-unassigned-import -- Vite extracts this component-owned stylesheet.
import "./ticket-watcher-panel.css";

type WatcherSnapshot =
  | { boundaryKey: string; kind: "loading" }
  | { boundaryKey: string; kind: "ready"; page: VersionedTicketWatcherPage }
  | { boundaryKey: string; kind: "error"; message: string };

export interface ReloadedTicketBoundary {
  etag: string;
  version: number;
}

export function TicketWatcherPanel({
  api,
  authorityEpoch,
  canEdit,
  canRead,
  csrfToken,
  kind,
  onReloadLatest,
  resourceId,
  sessionId,
  tenantId,
  ticketEtag,
  ticketVersion,
}: {
  api: TicketWatcherApi;
  authorityEpoch: string;
  canEdit: boolean;
  canRead: boolean;
  csrfToken: string;
  kind: TicketKind;
  onReloadLatest: () => Promise<ReloadedTicketBoundary | null>;
  resourceId: string;
  sessionId: string;
  tenantId: string;
  ticketEtag: string;
  ticketVersion: number;
}): React.JSX.Element | null {
  const id = useId();
  const boundaryKey = JSON.stringify([
    authorityEpoch,
    sessionId,
    tenantId,
    kind,
    resourceId,
    ticketEtag,
    ticketVersion,
    canRead,
    canEdit,
    csrfToken,
  ]);
  const [snapshot, setSnapshot] = useState<WatcherSnapshot>({
    boundaryKey,
    kind: "loading",
  });
  const [editorKey, setEditorKey] = useState(boundaryKey);
  const [userId, setUserId] = useState("");
  const [userIdError, setUserIdError] = useState<string | null>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const [recoveryVersionFloor, setRecoveryVersionFloor] = useState<
    number | null
  >(null);
  const [reloadRequired, setReloadRequired] = useState(false);
  const [savingUserId, setSavingUserId] = useState<string | null>(null);
  const readRequest = useRef<AbortController | null>(null);
  const mutationRequest = useRef<AbortController | null>(null);
  const authorizationEpoch = useRef({});
  const attempt = useRef<IdempotencyReference>({ current: null });
  const reloadLatest = useRef(onReloadLatest);

  useLayoutEffect(() => {
    reloadLatest.current = onReloadLatest;
  }, [onReloadLatest]);

  useLayoutEffect(() => {
    authorizationEpoch.current = {};
    readRequest.current?.abort();
    mutationRequest.current?.abort();
    readRequest.current = null;
    mutationRequest.current = null;
    setSnapshot({ boundaryKey, kind: "loading" });
    setEditorKey(boundaryKey);
    setUserId("");
    setUserIdError(null);
    setProblem(null);
    setRecoveryVersionFloor(null);
    setReloadRequired(false);
    setSavingUserId(null);
    attempt.current.current = null;
    return () => {
      authorizationEpoch.current = {};
      readRequest.current?.abort();
      mutationRequest.current?.abort();
    };
  }, [boundaryKey]);

  useEffect(() => {
    if (!canRead) return undefined;
    const token = authorizationEpoch.current;
    const controller = new AbortController();
    readRequest.current?.abort();
    readRequest.current = controller;
    void api
      .list({ kind, resourceId, signal: controller.signal, tenantId })
      .then((page) => {
        if (authorizationEpoch.current !== token || controller.signal.aborted) {
          return;
        }
        setSnapshot({ boundaryKey, kind: "ready", page });
        if (page.etag !== ticketEtag || page.value.version !== ticketVersion) {
          setRecoveryVersionFloor((current) =>
            Math.max(current ?? 0, page.value.version, ticketVersion),
          );
          setReloadRequired(true);
          void reloadLatest.current().catch(() => undefined);
        }
      })
      .catch((error: unknown) => {
        if (
          authorizationEpoch.current !== token ||
          controller.signal.aborted ||
          isAbortError(error)
        ) {
          return;
        }
        setSnapshot({
          boundaryKey,
          kind: "error",
          message: watcherProblem(
            error,
            "The watcher list could not be loaded.",
          ),
        });
      })
      .finally(() => {
        if (readRequest.current === controller) readRequest.current = null;
      });
    return () => controller.abort();
  }, [
    api,
    boundaryKey,
    canRead,
    kind,
    resourceId,
    tenantId,
    ticketEtag,
    ticketVersion,
  ]);

  const snapshotIsCurrent = snapshot.boundaryKey === boundaryKey;
  const editorIsCurrent = editorKey === boundaryKey;
  const page =
    snapshotIsCurrent && snapshot.kind === "ready" ? snapshot.page : null;
  const pageMatchesTicket =
    page?.etag === ticketEtag && page.value.version === ticketVersion;
  const mutationOpen =
    canEdit &&
    canRead &&
    editorIsCurrent &&
    page !== null &&
    pageMatchesTicket &&
    !reloadRequired &&
    savingUserId === null;

  if (!canRead) return null;

  const changeUserId = (value: string): void => {
    setUserId(value);
    setUserIdError(null);
    setProblem(null);
    attempt.current.current = null;
  };

  const addWatcher = (event: FormEvent<HTMLFormElement>): void => {
    event.preventDefault();
    const normalized = userId.trim().toLowerCase();
    if (!watcherUuidV7Pattern.test(normalized)) {
      setUserIdError(
        "Enter the canonical UUIDv7 of an eligible tenant operator.",
      );
      return;
    }
    void mutate("add", normalized);
  };

  const mutate = async (
    action: "add" | "remove",
    targetUserId: string,
  ): Promise<void> => {
    if (!mutationOpen || !page) return;
    const payload = {
      action,
      expectedVersion: page.value.version,
      kind,
      operation: "mutate-ticket-watcher-set",
      resourceId,
      sessionId,
      targetUserId,
      tenantId,
    };
    const idempotencyKey = idempotencyKeyForPayload(attempt.current, payload);
    const token = authorizationEpoch.current;
    const controller = new AbortController();
    mutationRequest.current?.abort();
    mutationRequest.current = controller;
    setProblem(null);
    setUserIdError(null);
    setSavingUserId(targetUserId);
    try {
      const result = await api.mutate({
        action,
        csrfToken,
        etag: page.etag,
        expectedVersion: page.value.version,
        idempotencyKey,
        kind,
        resourceId,
        signal: controller.signal,
        tenantId,
        userId: targetUserId,
      });
      if (
        authorizationEpoch.current !== token ||
        mutationRequest.current !== controller ||
        controller.signal.aborted
      ) {
        return;
      }
      attempt.current.current = null;
      if (action === "add") setUserId("");
      if (result.replayed) {
        setRecoveryVersionFloor(result.value.version);
        setReloadRequired(true);
        await synchronize(token, result.value.version);
        return;
      }
      setSnapshot({ boundaryKey, kind: "ready", page: result });
      if (result.changed) {
        setRecoveryVersionFloor(result.value.version);
        setReloadRequired(true);
        const reloaded = await reloadLatest.current().catch(() => false);
        if (authorizationEpoch.current !== token) return;
        if (!reloaded) {
          setProblem(
            "The watcher change was saved, but the latest ticket snapshot could not be loaded. Reload before changing watchers again.",
          );
        }
      }
    } catch (error) {
      if (
        authorizationEpoch.current !== token ||
        controller.signal.aborted ||
        isAbortError(error)
      ) {
        return;
      }
      setProblem(
        watcherProblem(error, "The watcher list could not be updated."),
      );
      if (
        error instanceof TicketWatcherApiError &&
        (error.status === 412 || error.status === 428)
      ) {
        const requiredVersion = ticketVersion + 1;
        setRecoveryVersionFloor(requiredVersion);
        setReloadRequired(true);
        await synchronize(token, requiredVersion);
      }
    } finally {
      if (
        authorizationEpoch.current === token &&
        mutationRequest.current === controller
      ) {
        mutationRequest.current = null;
        setSavingUserId(null);
      }
    }
  };

  const synchronize = async (
    token = authorizationEpoch.current,
    requiredVersion = recoveryVersionFloor,
  ): Promise<void> => {
    readRequest.current?.abort();
    const controller = new AbortController();
    readRequest.current = controller;
    const [watchersResult, reloadedTicket] = await Promise.all([
      api
        .list({ kind, resourceId, signal: controller.signal, tenantId })
        .then((value) => ({ kind: "success" as const, value }))
        .catch((error: unknown) => ({ error, kind: "error" as const })),
      reloadLatest.current().catch(() => null),
    ]);
    if (
      authorizationEpoch.current !== token ||
      controller.signal.aborted ||
      readRequest.current !== controller
    ) {
      return;
    }
    readRequest.current = null;
    if (watchersResult.kind === "success") {
      setSnapshot({ boundaryKey, kind: "ready", page: watchersResult.value });
    } else if (!isAbortError(watchersResult.error)) {
      setSnapshot({
        boundaryKey,
        kind: "error",
        message: watcherProblem(
          watchersResult.error,
          "The latest watcher list could not be loaded.",
        ),
      });
    }
    if (
      reloadedTicket !== null &&
      watchersResult.kind === "success" &&
      watchersResult.value.etag === reloadedTicket.etag &&
      watchersResult.value.value.version === reloadedTicket.version &&
      reloadedTicket.etag === ticketEtag &&
      reloadedTicket.version === ticketVersion &&
      (requiredVersion === null ||
        watchersResult.value.value.version >= requiredVersion)
    ) {
      setProblem(null);
      setRecoveryVersionFloor(null);
      setReloadRequired(false);
    } else {
      setReloadRequired(true);
    }
  };

  return (
    <section className="ticket-watchers" aria-labelledby={`${id}-heading`}>
      <header className="ticket-watchers__heading">
        <span>
          <UsersRound aria-hidden="true" />
          <span>
            <h3 id={`${id}-heading`}>Watchers</h3>
            <small>Tenant operators · private projection</small>
          </span>
        </span>
        {page ? (
          <span className="ticket-watchers__snapshot">
            Snapshot <strong>v{page.value.version}</strong>
          </span>
        ) : null}
      </header>

      {problem && snapshotIsCurrent ? (
        <p className="ticket-watchers__problem" role="alert">
          {problem}
        </p>
      ) : null}

      {!snapshotIsCurrent || snapshot.kind === "loading" ? (
        <p className="ticket-watchers__status" role="status">
          Loading watchers…
        </p>
      ) : null}
      {snapshotIsCurrent && snapshot.kind === "error" ? (
        <div className="ticket-watchers__status ticket-watchers__status--error">
          <p role="alert">{snapshot.message}</p>
          <Button
            type="button"
            variant="outline"
            onClick={() => void synchronize()}
          >
            <RefreshCw aria-hidden="true" /> Retry watchers
          </Button>
        </div>
      ) : null}
      {page ? (
        <>
          {page.value.items.length > 0 ? (
            <ul className="ticket-watchers__list" aria-label="Ticket watchers">
              {page.value.items.map((watcher) => (
                <li key={watcher.userId}>
                  <span>
                    <strong>{watcher.displayName}</strong>
                    <code>{watcher.userId}</code>
                    <small>
                      Watching since <TenantInstant value={watcher.addedAt} />
                    </small>
                  </span>
                  {mutationOpen ? (
                    <Button
                      aria-label={`Remove ${watcher.displayName} (${watcher.userId}) from watchers`}
                      disabled={savingUserId !== null}
                      onClick={() => void mutate("remove", watcher.userId)}
                      type="button"
                      variant="outline"
                    >
                      <Trash2 aria-hidden="true" />
                      {savingUserId === watcher.userId ? "Removing…" : "Remove"}
                    </Button>
                  ) : null}
                </li>
              ))}
            </ul>
          ) : (
            <p className="ticket-watchers__status">
              No operators are watching this ticket.
            </p>
          )}

          {canEdit && editorIsCurrent && !reloadRequired ? (
            <form
              className="ticket-watchers__add"
              onSubmit={addWatcher}
              noValidate
            >
              <span>
                <Label htmlFor={`${id}-user-id`}>Operator user ID</Label>
                <small>
                  Enter an active tenant operator with live read access to this
                  ticket.
                </small>
              </span>
              <Input
                aria-describedby={
                  userIdError ? `${id}-user-id-error` : `${id}-user-id-hint`
                }
                aria-invalid={Boolean(userIdError)}
                autoComplete="off"
                disabled={savingUserId !== null}
                id={`${id}-user-id`}
                onChange={(event) => changeUserId(event.target.value)}
                placeholder="018f6b31-2cc8-7b3c-9d81-9a770a4f5d32"
                value={userId}
              />
              <span className="ticket-watchers__add-action">
                <Button
                  disabled={!mutationOpen || userId.trim() === ""}
                  type="submit"
                >
                  <UserPlus aria-hidden="true" />
                  {savingUserId ? "Updating…" : "Add watcher"}
                </Button>
              </span>
              <small
                className="ticket-watchers__hint"
                id={`${id}-user-id-hint`}
              >
                Customer contacts are never eligible watchers.
              </small>
              {userIdError ? (
                <small
                  className="ticket-watchers__field-error"
                  id={`${id}-user-id-error`}
                  role="alert"
                >
                  {userIdError}
                </small>
              ) : null}
            </form>
          ) : null}
          {!canEdit ? (
            <p className="ticket-watchers__status">
              Watchers are read-only under the current live tenant authority.
            </p>
          ) : null}
          {reloadRequired ? (
            <div className="ticket-watchers__reload">
              <Button
                type="button"
                variant="outline"
                onClick={() => void synchronize()}
              >
                <RefreshCw aria-hidden="true" /> Reload latest watcher snapshot
              </Button>
            </div>
          ) : null}
        </>
      ) : null}
    </section>
  );
}

function watcherProblem(error: unknown, fallback: string): string {
  return error instanceof TicketWatcherApiError ? error.message : fallback;
}

function isAbortError(error: unknown): boolean {
  return error instanceof DOMException && error.name === "AbortError";
}
