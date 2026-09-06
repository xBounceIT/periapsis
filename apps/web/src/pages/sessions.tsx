import { Badge } from "@periapsis/ui/components/ui/badge";
import { Button } from "@periapsis/ui/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@periapsis/ui/components/ui/card";
import {
  Clock3,
  KeyRound,
  Laptop,
  RefreshCw,
  ShieldCheck,
  Trash2,
} from "lucide-react";
import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { useNavigate } from "react-router";
import { appendUniqueSessions } from "./sessions-model";

import { useSession } from "../auth/session-context";
import { FocusedError } from "../components/focused-error";
import {
  describePhaseTwoError,
  PhaseTwoApiError,
  type AuthenticationMethod,
  type SessionSummaryView,
} from "../lib/phase-two-types";
import { TenantInstant } from "../lib/tenant-date-time-context";

type SessionListState =
  | { kind: "error"; message: string }
  | {
      items: readonly SessionSummaryView[];
      kind: "ready";
      nextCursor?: string;
    }
  | { kind: "loading" };

export function SessionsPage(): React.JSX.Element {
  const model = useSessionsPageModel();
  return <SessionsPageView model={model.data} />;
}

function useSessionsPageModel() {
  const { api, clearSession, session } = useSession();
  const [listState, setListState] = useState<SessionListState>({
    kind: "loading",
  });
  const [loadAttempt, setLoadAttempt] = useState(0);
  const [confirmingId, setConfirmingId] = useState<string | null>(null);
  const [revokingId, setRevokingId] = useState<string | null>(null);
  const [revokeError, setRevokeError] = useState<string | null>(null);
  const [isLoadingMore, setIsLoadingMore] = useState(false);
  const [paginationError, setPaginationError] = useState<string | null>(null);
  const navigate = useNavigate();
  const sessionIdRef = useRef(session.id);
  useLayoutEffect(() => {
    sessionIdRef.current = session.id;
  }, [session]);

  useEffect(() => {
    setIsLoadingMore(false);
    setPaginationError(null);
    setConfirmingId(null);
    setRevokingId(null);
    setRevokeError(null);
  }, [session.id]);

  useEffect(() => {
    let cancelled = false;
    setListState({ kind: "loading" });
    setRevokeError(null);

    void api
      .listSessions()
      .then((page) => {
        if (!cancelled) {
          setListState({ kind: "ready", ...page });
        }
      })
      .catch((caught: unknown) => {
        if (cancelled) {
          return;
        }
        if (caught instanceof PhaseTwoApiError && caught.status === 401) {
          clearSession(session.id);
          return;
        }
        setListState({
          kind: "error",
          message: describePhaseTwoError(
            caught,
            "Session metadata could not be loaded.",
          ),
        });
      });

    return () => {
      cancelled = true;
    };
  }, [api, clearSession, loadAttempt, session.id]);

  async function loadMore(): Promise<void> {
    if (listState.kind !== "ready" || !listState.nextCursor || isLoadingMore) {
      return;
    }
    const requestedCursor = listState.nextCursor;
    const requestedSessionId = session.id;
    setIsLoadingMore(true);
    setPaginationError(null);
    try {
      const page = await api.listSessions(requestedCursor);
      if (sessionIdRef.current !== requestedSessionId) {
        return;
      }
      if (page.nextCursor === requestedCursor) {
        throw new Error("The session cursor did not advance.");
      }
      setListState((current) =>
        current.kind === "ready" && current.nextCursor === requestedCursor
          ? {
              items: appendUniqueSessions(current.items, page.items),
              kind: "ready",
              ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
            }
          : current,
      );
    } catch (caught) {
      if (sessionIdRef.current !== requestedSessionId) {
        return;
      }
      if (caught instanceof PhaseTwoApiError && caught.status === 401) {
        void navigate("/");
        clearSession(requestedSessionId);
        return;
      }
      setPaginationError(
        describePhaseTwoError(caught, "More sessions could not be loaded."),
      );
    } finally {
      if (sessionIdRef.current === requestedSessionId) {
        // react-doctor-disable-next-line no-loading-flag-reset-outside-finally -- The owning request clears this flag in finally; the generation guard protects newer requests.
        setIsLoadingMore(false);
      }
    }
  }

  async function revoke(item: SessionSummaryView): Promise<void> {
    const requestedSessionId = session.id;
    setRevokeError(null);
    setRevokingId(item.id);
    try {
      await api.revokeSession(session.csrfToken, item.id);
      if (sessionIdRef.current !== requestedSessionId) {
        return;
      }
      if (isCurrentSession(item, sessionIdRef.current)) {
        void navigate("/");
        clearSession(requestedSessionId);
        return;
      }
      setListState((current) =>
        current.kind === "ready"
          ? {
              kind: "ready",
              items: current.items.filter(
                (candidate) => candidate.id !== item.id,
              ),
              ...(current.nextCursor ? { nextCursor: current.nextCursor } : {}),
            }
          : current,
      );
      setConfirmingId(null);
    } catch (caught) {
      if (sessionIdRef.current !== requestedSessionId) {
        return;
      }
      if (caught instanceof PhaseTwoApiError && caught.status === 401) {
        void navigate("/");
        clearSession(requestedSessionId);
        return;
      }
      setRevokeError(
        describePhaseTwoError(
          caught,
          "The server did not revoke this session. It remains active.",
        ),
      );
    } finally {
      if (sessionIdRef.current === requestedSessionId) {
        setRevokingId(null);
      }
    }
  }

  return {
    kind: "ready" as const,
    data: {
      confirmingId,
      isLoadingMore,
      listState,
      loadMore,
      paginationError,
      revoke,
      revokeError,
      revokingId,
      session,
      setConfirmingId,
      setLoadAttempt,
      setRevokeError,
    },
  };
}

function SessionsPageView({
  model,
}: {
  model: Extract<
    ReturnType<typeof useSessionsPageModel>,
    { kind: "ready" }
  >["data"];
}): React.JSX.Element {
  const {
    confirmingId,
    isLoadingMore,
    listState,
    loadMore,
    paginationError,
    revoke,
    revokeError,
    revokingId,
    session,
    setConfirmingId,
    setLoadAttempt,
    setRevokeError,
  } = model;
  return (
    <div className="content sessions-page">
      <section className="page-heading" aria-labelledby="sessions-page-title">
        <div>
          <p className="section-label">Session lifecycle</p>
          <h1 id="sessions-page-title">Operator sessions</h1>
          <p>
            Review server-held metadata and revoke access that is no longer
            expected. Session credentials and token digests are never returned
            to this page.
          </p>
        </div>
        <Badge variant="outline">
          <ShieldCheck aria-hidden="true" /> Protected by CSRF
        </Badge>
      </section>

      {revokeError ? (
        <FocusedError message={revokeError} title="Session revocation failed" />
      ) : null}
      {paginationError ? (
        <FocusedError
          message={paginationError}
          title="More sessions could not be loaded"
        />
      ) : null}

      {listState.kind === "loading" ? <SessionListSkeleton /> : null}
      {listState.kind === "error" ? (
        <div className="session-list-error">
          <FocusedError message={listState.message} />
          <Button
            type="button"
            variant="outline"
            onClick={() => setLoadAttempt((attempt) => attempt + 1)}
          >
            <RefreshCw aria-hidden="true" /> Retry session list
          </Button>
        </div>
      ) : null}
      {listState.kind === "ready" && listState.items.length === 0 ? (
        <div className="tenant-empty">
          <Laptop aria-hidden="true" />
          <h2>No active sessions returned</h2>
          <p>The current session may have expired. Revalidate access.</p>
        </div>
      ) : null}
      {listState.kind === "ready" && listState.items.length > 0 ? (
        <div className="session-list">
          {listState.items.map((item) => (
            <Card key={item.id} className="session-card">
              <CardHeader>
                <span className="session-card__icon" aria-hidden="true">
                  <Laptop />
                </span>
                <div>
                  <CardTitle>
                    {isCurrentSession(item, session.id)
                      ? "This browser session"
                      : "Operator session"}
                  </CardTitle>
                  <CardDescription>
                    Created <TenantInstant value={item.createdAt} />
                  </CardDescription>
                </div>
                <SessionStatusBadge item={item} sessionId={session.id} />
              </CardHeader>
              <CardContent>
                <dl className="session-metadata">
                  <div>
                    <dt>
                      <KeyRound aria-hidden="true" /> Authentication
                    </dt>
                    <dd>
                      {formatAuthenticationMethod(item.authenticationMethod)}
                    </dd>
                  </div>
                  <div>
                    <dt>
                      <Clock3 aria-hidden="true" /> Last seen
                    </dt>
                    <dd>
                      <TenantInstant value={item.lastSeenAt} />
                    </dd>
                  </div>
                  <div>
                    <dt>Idle expiry</dt>
                    <dd>
                      <TenantInstant value={item.idleExpiresAt} />
                    </dd>
                  </div>
                  <div>
                    <dt>Absolute expiry</dt>
                    <dd>
                      <TenantInstant value={item.absoluteExpiresAt} />
                    </dd>
                  </div>
                  {item.revokedAt ? (
                    <div>
                      <dt>Revoked</dt>
                      <dd>
                        <TenantInstant value={item.revokedAt} />
                      </dd>
                    </div>
                  ) : null}
                </dl>

                {isSessionInactive(item) ? null : confirmingId === item.id ? (
                  <div className="revoke-confirmation" role="alert">
                    <p>
                      {isCurrentSession(item, session.id)
                        ? "Revoking this session signs this browser out immediately."
                        : "Revoke this session now? The operator must authenticate again."}
                    </p>
                    <div>
                      <Button
                        type="button"
                        variant="destructive"
                        size="sm"
                        disabled={revokingId === item.id}
                        onClick={() => void revoke(item)}
                      >
                        <Trash2 aria-hidden="true" />
                        {revokingId === item.id
                          ? "Revoking…"
                          : "Confirm revoke"}
                      </Button>
                      <Button
                        type="button"
                        variant="ghost"
                        size="sm"
                        disabled={revokingId === item.id}
                        onClick={() => setConfirmingId(null)}
                      >
                        Keep session
                      </Button>
                    </div>
                  </div>
                ) : (
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={() => {
                      setRevokeError(null);
                      setConfirmingId(item.id);
                    }}
                  >
                    <Trash2 aria-hidden="true" />
                    {isCurrentSession(item, session.id)
                      ? "Revoke and sign out"
                      : "Revoke session"}
                  </Button>
                )}
              </CardContent>
            </Card>
          ))}
          {listState.nextCursor ? (
            <Button
              type="button"
              variant="outline"
              disabled={isLoadingMore}
              onClick={() => void loadMore()}
            >
              {isLoadingMore ? "Loading more sessions…" : "Load more sessions"}
            </Button>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}

function SessionStatusBadge({
  item,
  sessionId,
}: {
  item: SessionSummaryView;
  sessionId: string;
}): React.JSX.Element {
  if (item.revokedAt) {
    return <Badge variant="outline">Revoked</Badge>;
  }
  if (isSessionExpired(item)) {
    return <Badge variant="outline">Expired</Badge>;
  }
  return (
    <Badge
      variant={isCurrentSession(item, sessionId) ? "secondary" : "outline"}
    >
      {isCurrentSession(item, sessionId) ? "Current" : "Active"}
    </Badge>
  );
}

function isCurrentSession(
  item: SessionSummaryView,
  sessionId: string,
): boolean {
  return item.current && item.id === sessionId;
}

function isSessionInactive(item: SessionSummaryView): boolean {
  return Boolean(item.revokedAt) || isSessionExpired(item);
}

function isSessionExpired(item: SessionSummaryView): boolean {
  const idleExpiry = Date.parse(item.idleExpiresAt);
  const absoluteExpiry = Date.parse(item.absoluteExpiresAt);
  return (
    (!Number.isNaN(idleExpiry) && idleExpiry <= Date.now()) ||
    (!Number.isNaN(absoluteExpiry) && absoluteExpiry <= Date.now())
  );
}

function SessionListSkeleton(): React.JSX.Element {
  return (
    <div
      className="session-list-skeleton"
      aria-label="Loading operator sessions"
    >
      <span />
      <span />
    </div>
  );
}

function formatAuthenticationMethod(value: AuthenticationMethod): string {
  switch (value) {
    case "bootstrap_totp":
      return "Bootstrap + TOTP";
    case "oidc":
      return "OpenID Connect";
    case "passkey":
      return "Passkey";
    case "recovery_code":
      return "Recovery code";
    case "saml":
      return "SAML 2.0";
    case "totp":
      return "TOTP";
    default:
      return "Unknown authentication method";
  }
}
