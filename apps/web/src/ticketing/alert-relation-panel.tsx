import { useInfiniteQuery, useQueryClient } from "@tanstack/react-query";
import type {
  AlertRelation,
  AlertRelationMutationReceipt,
  AlertRelationType,
} from "@periapsis/contracts";
import { Badge } from "@periapsis/ui/components/ui/badge";
import { Button } from "@periapsis/ui/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@periapsis/ui/components/ui/dialog";
import { Input } from "@periapsis/ui/components/ui/input";
import { Label } from "@periapsis/ui/components/ui/label";
import { Textarea } from "@periapsis/ui/components/ui/textarea";
import {
  ArrowDown,
  GitCompareArrows,
  Link2,
  RefreshCw,
  RotateCcw,
  ShieldAlert,
} from "lucide-react";
import {
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
  type FormEvent,
} from "react";
import { Link } from "react-router";

import { FocusedError } from "../components/focused-error";
import {
  idempotencyKeyForPayload,
  type IdempotencyReference,
} from "../lib/payload-idempotency";
import { TenantInstant } from "../lib/tenant-date-time-context";
import {
  describeTicketingError,
  type TicketingApi,
} from "../lib/ticketing-api";
import {
  AlertRelationApiError,
  alertRelationApi,
  alertRelationUuidV7Pattern,
  isCanonicalAlertRelationReason,
  type AlertRelationApi,
  type AlertRelationPage,
} from "./alert-relation-api";
import { useTicketingApi } from "./ticketing-context";
import { humanizeKey, severityTone } from "./ticketing-model";

// oxlint-disable-next-line import/no-unassigned-import -- Vite extracts this component-owned stylesheet.
import "./alert-relation-panel.css";

export interface ReloadedAlertBoundary {
  etag: string;
  version: number;
}

export function AlertRelationPanel({
  alertEtag,
  alertId,
  alertVersion,
  api = alertRelationApi,
  authorityEpoch,
  canManage,
  csrfToken,
  onReloadLatest,
  sessionId,
  tenantId,
  ticketApi,
}: {
  alertEtag: string;
  alertId: string;
  alertVersion: number;
  api?: AlertRelationApi;
  authorityEpoch: string;
  canManage: boolean;
  csrfToken: string;
  onReloadLatest: () => Promise<ReloadedAlertBoundary | null>;
  sessionId: string;
  tenantId: string;
  ticketApi?: TicketingApi;
}): React.JSX.Element | null {
  const contextTicketApi = useTicketingApi();
  const tickets = ticketApi ?? contextTicketApi;
  const queryClient = useQueryClient();
  const authorizationBoundary = JSON.stringify([
    authorityEpoch,
    alertId,
    canManage,
    csrfToken,
    sessionId,
    tenantId,
  ]);
  const queryKey = [
    "alert-relations",
    authorizationBoundary,
    tenantId,
    alertId,
  ] as const;
  const query = useInfiniteQuery({
    enabled: canManage,
    initialPageParam: undefined as string | undefined,
    queryKey,
    queryFn: ({ pageParam, signal }) =>
      api.list({
        ...(pageParam === undefined ? {} : { after: pageParam }),
        alertId,
        limit: 50,
        signal,
        tenantId,
      }),
    getNextPageParam: safeNextCursor,
    retry: (count, error) =>
      !(
        error instanceof AlertRelationApiError &&
        [401, 403, 404].includes(error.status ?? 0)
      ) && count < 1,
  });
  const projection = flattenAlertRelationPages(query.data?.pages);
  const [createOpen, setCreateOpen] = useState(false);
  const [relationType, setRelationType] =
    useState<AlertRelationType>("correlation");
  const [targetAlertId, setTargetAlertId] = useState("");
  const [createReason, setCreateReason] = useState("");
  const [retracting, setRetracting] = useState<AlertRelation | null>(null);
  const [retractionReason, setRetractionReason] = useState("");
  const [busy, setBusy] = useState<"create" | "retract" | null>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [reloadRequired, setReloadRequired] = useState(false);
  const [minimumAlertVersion, setMinimumAlertVersion] = useState<number | null>(
    null,
  );
  const mutationRequest = useRef<AbortController | null>(null);
  const authorizationToken = useRef({});
  const attempt = useRef<IdempotencyReference>({ current: null });
  const reloadLatest = useRef(onReloadLatest);
  const snapshotBoundary = `${alertEtag}:${alertVersion}`;
  const alertBoundaryIsCanonical = alertEtag === `"v${alertVersion}"`;

  useLayoutEffect(() => {
    reloadLatest.current = onReloadLatest;
  }, [onReloadLatest]);

  useLayoutEffect(() => {
    authorizationToken.current = {};
    mutationRequest.current?.abort();
    mutationRequest.current = null;
    attempt.current.current = null;
    setCreateOpen(false);
    setTargetAlertId("");
    setRelationType("correlation");
    setCreateReason("");
    setRetracting(null);
    setRetractionReason("");
    setBusy(null);
    setProblem(null);
    setNotice(null);
    setReloadRequired(false);
    setMinimumAlertVersion(null);
    return () => {
      authorizationToken.current = {};
      mutationRequest.current?.abort();
      void queryClient.cancelQueries({ exact: true, queryKey });
      queryClient.removeQueries({ exact: true, queryKey });
    };
  }, [authorizationBoundary, queryClient]);

  useLayoutEffect(() => {
    mutationRequest.current?.abort();
    mutationRequest.current = null;
    setBusy(null);
  }, [snapshotBoundary]);

  useEffect(() => {
    if (
      minimumAlertVersion !== null &&
      alertBoundaryIsCanonical &&
      alertVersion >= minimumAlertVersion
    ) {
      setMinimumAlertVersion(null);
      setReloadRequired(false);
    }
  }, [alertBoundaryIsCanonical, alertVersion, minimumAlertVersion]);

  if (!canManage) return null;

  const canMutate =
    alertBoundaryIsCanonical &&
    alertVersion < 2_147_483_647 &&
    projection.canonical &&
    !reloadRequired &&
    busy === null &&
    !query.isPending &&
    !query.isError;
  const createDraftIsValid =
    alertRelationUuidV7Pattern.test(targetAlertId) &&
    targetAlertId !== alertId &&
    isCanonicalAlertRelationReason(createReason);
  const retractionDraftIsValid =
    isCanonicalAlertRelationReason(retractionReason);

  const changeCreateOpen = (next: boolean): void => {
    if (!next) mutationRequest.current?.abort();
    setCreateOpen(next);
    setProblem(null);
    setNotice(null);
    if (!next) {
      setTargetAlertId("");
      setRelationType("correlation");
      setCreateReason("");
      setBusy(null);
      attempt.current.current = null;
    }
  };

  const closeRetraction = (): void => {
    mutationRequest.current?.abort();
    mutationRequest.current = null;
    attempt.current.current = null;
    setRetracting(null);
    setRetractionReason("");
    setBusy(null);
    setProblem(null);
  };

  const submitCreate = (event: FormEvent<HTMLFormElement>): void => {
    event.preventDefault();
    if (!canMutate || !createDraftIsValid) return;
    void mutate({
      kind: "create",
      reason: createReason,
      relationType,
      targetAlertId,
    });
  };

  const submitRetraction = (event: FormEvent<HTMLFormElement>): void => {
    event.preventDefault();
    if (!canMutate || !retracting || !retractionDraftIsValid) return;
    void mutate({
      kind: "retract",
      reason: retractionReason,
      relation: retracting,
    });
  };

  const ownsMutation = (token: object, controller: AbortController): boolean =>
    authorizationToken.current === token &&
    mutationRequest.current === controller &&
    !controller.signal.aborted;

  const mutate = async (
    command:
      | {
          kind: "create";
          reason: string;
          relationType: AlertRelationType;
          targetAlertId: string;
        }
      | { kind: "retract"; reason: string; relation: AlertRelation },
  ): Promise<void> => {
    if (!canMutate) return;
    const relatedAlertId =
      command.kind === "create"
        ? command.targetAlertId
        : command.relation.relatedAlert.id;
    const token = authorizationToken.current;
    const controller = new AbortController();
    mutationRequest.current?.abort();
    mutationRequest.current = controller;
    setBusy(command.kind);
    setProblem(null);
    setNotice(null);
    try {
      const related = await tickets.getTicket(
        "alert",
        tenantId,
        relatedAlertId,
        controller.signal,
      );
      if (
        !ownsMutation(token, controller) ||
        related.value.projection !== "operator" ||
        related.value.tenantId !== tenantId ||
        related.value.id !== relatedAlertId ||
        related.etag !== `"v${related.value.version}"` ||
        related.value.version >= 2_147_483_647
      ) {
        throw new Error("Current operator snapshots are required.");
      }
      const payload = {
        alertId,
        alertVersion,
        command:
          command.kind === "create"
            ? {
                kind: command.kind,
                reason: command.reason,
                relationType: command.relationType,
                targetAlertId: command.targetAlertId,
              }
            : {
                kind: command.kind,
                reason: command.reason,
                relatedAlertId,
                relationId: command.relation.id,
              },
        operation: "mutate-alert-relation",
        relatedAlertVersion: related.value.version,
        sessionId,
        tenantId,
      };
      const idempotencyKey = idempotencyKeyForPayload(attempt.current, payload);
      const common = {
        alertEtag,
        alertId,
        csrfToken,
        expectedAlertVersion: alertVersion,
        idempotencyKey,
        reason: command.reason,
        signal: controller.signal,
        tenantId,
      };
      const receipt =
        command.kind === "create"
          ? await api.create({
              ...common,
              expectedTargetVersion: related.value.version,
              relationType: command.relationType,
              targetAlertId: command.targetAlertId,
            })
          : await api.retract({
              ...common,
              expectedRelatedAlertVersion: related.value.version,
              relation: command.relation,
            });
      if (!ownsMutation(token, controller)) return;
      attempt.current.current = null;
      if (command.kind === "create") {
        setCreateOpen(false);
        setTargetAlertId("");
        setCreateReason("");
        setRelationType("correlation");
      } else {
        setRetracting(null);
        setRetractionReason("");
      }
      setNotice(
        receipt.replayed
          ? "The original relationship result was replayed safely."
          : command.kind === "create"
            ? "Alert relationship recorded without merging either Alert."
            : "Retraction appended; the original relationship remains immutable.",
      );
      setMinimumAlertVersion(receipt.alertVersion);
      await refreshAfterMutation(receipt, relatedAlertId, token, controller);
    } catch (error) {
      if (!ownsMutation(token, controller) || isAbortError(error)) return;
      setProblem(alertRelationProblem(error));
      if (
        error instanceof AlertRelationApiError &&
        (error.status === 412 || error.status === 428)
      ) {
        setReloadRequired(true);
        const latest = await reloadLatest.current();
        if (
          ownsMutation(token, controller) &&
          isReloadedAlertBoundary(latest)
        ) {
          if (latest.version > alertVersion) {
            setMinimumAlertVersion(latest.version);
          } else if (latest.version === alertVersion) {
            setReloadRequired(false);
          }
        }
      }
    } finally {
      if (ownsMutation(token, controller)) {
        mutationRequest.current = null;
        setBusy(null);
      }
    }
  };

  const refreshAfterMutation = async (
    receipt: AlertRelationMutationReceipt,
    relatedAlertId: string,
    token: object,
    controller: AbortController,
  ): Promise<void> => {
    setReloadRequired(true);
    await Promise.all([
      queryClient.invalidateQueries({ queryKey }),
      queryClient.invalidateQueries({
        queryKey: ["ticket", "alert", tenantId, relatedAlertId],
      }),
      queryClient.invalidateQueries({
        queryKey: ["ticket-activity", "alert", tenantId, alertId],
      }),
      queryClient.invalidateQueries({
        queryKey: ["ticket-activity", "alert", tenantId, relatedAlertId],
      }),
      queryClient.invalidateQueries({
        queryKey: ["tickets", "alert", tenantId],
      }),
    ]);
    const latest = await reloadLatest.current();
    if (!ownsMutation(token, controller)) return;
    if (
      !isReloadedAlertBoundary(latest) ||
      latest.version < receipt.alertVersion
    ) {
      setProblem(
        "The relationship was saved, but the latest Alert snapshot could not be loaded. Reload before changing relationships again.",
      );
      return;
    }
    if (alertBoundaryIsCanonical && alertVersion >= receipt.alertVersion) {
      setReloadRequired(false);
    }
  };

  const reloadWorkspace = async (): Promise<void> => {
    setProblem(null);
    const [latest] = await Promise.all([
      reloadLatest.current(),
      query.refetch(),
    ]);
    const minimumVersion = minimumAlertVersion ?? alertVersion;
    if (!isReloadedAlertBoundary(latest) || latest.version < minimumVersion) {
      setReloadRequired(true);
      return;
    }
    if (latest.version > alertVersion) {
      setMinimumAlertVersion(latest.version);
      setReloadRequired(true);
      return;
    }
    setReloadRequired(false);
  };

  return (
    <section
      className="alert-relation-panel"
      aria-labelledby="alert-relation-title"
    >
      <header className="alert-relation-panel__header">
        <div>
          <p className="section-label">Explicit evidence</p>
          <h2 id="alert-relation-title">Related Alerts</h2>
          <p>
            Classify duplicates and correlations without merging state,
            evidence, or ownership.
          </p>
        </div>
        <Dialog open={createOpen} onOpenChange={changeCreateOpen}>
          <DialogTrigger asChild>
            <Button disabled={!canMutate}>
              <Link2 aria-hidden="true" /> Add relationship
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Relate another Alert</DialogTitle>
              <DialogDescription>
                Both current Alert versions are pinned. This creates immutable
                evidence and does not close, copy, or merge either Alert.
              </DialogDescription>
            </DialogHeader>
            <form className="alert-relation-form" onSubmit={submitCreate}>
              <div>
                <Label htmlFor="alert-relation-target">Target Alert ID</Label>
                <Input
                  autoComplete="off"
                  autoFocus
                  disabled={busy !== null}
                  id="alert-relation-target"
                  maxLength={36}
                  onChange={(event) => {
                    setTargetAlertId(event.currentTarget.value);
                    setProblem(null);
                    attempt.current.current = null;
                  }}
                  pattern={alertRelationUuidV7Pattern.source}
                  placeholder="019… UUIDv7"
                  required
                  spellCheck={false}
                  value={targetAlertId}
                />
              </div>
              <div>
                <Label htmlFor="alert-relation-type">Relationship</Label>
                <select
                  disabled={busy !== null}
                  id="alert-relation-type"
                  onChange={(event) => {
                    const value = event.currentTarget.value;
                    if (value === "correlation" || value === "duplicate_of") {
                      setRelationType(value);
                      setProblem(null);
                      attempt.current.current = null;
                    }
                  }}
                  value={relationType}
                >
                  <option value="correlation">Correlated with</option>
                  <option value="duplicate_of">Duplicate of</option>
                </select>
              </div>
              <div>
                <Label htmlFor="alert-relation-reason">Reason</Label>
                <Textarea
                  disabled={busy !== null}
                  id="alert-relation-reason"
                  maxLength={2000}
                  onChange={(event) => {
                    setCreateReason(event.currentTarget.value);
                    setProblem(null);
                    attempt.current.current = null;
                  }}
                  placeholder="State the concrete evidence connecting these Alerts"
                  required
                  value={createReason}
                />
                <small>Plain text, up to 2,000 UTF-8 bytes.</small>
              </div>
              {problem ? <p role="alert">{problem}</p> : null}
              <div className="alert-relation-form__actions">
                <Button
                  disabled={busy !== null}
                  onClick={() => changeCreateOpen(false)}
                  type="button"
                  variant="ghost"
                >
                  Cancel
                </Button>
                <Button
                  disabled={!canMutate || !createDraftIsValid}
                  type="submit"
                >
                  {busy === "create" ? "Recording…" : "Record relationship"}
                </Button>
              </div>
            </form>
          </DialogContent>
        </Dialog>
      </header>

      {notice ? <p className="alert-relation-panel__notice">{notice}</p> : null}
      {reloadRequired ? (
        <div className="alert-relation-panel__recovery" role="alert">
          <ShieldAlert aria-hidden="true" />
          <p>
            Reload both relationship evidence and the current Alert snapshot.
          </p>
          <Button
            size="sm"
            variant="outline"
            onClick={() => void reloadWorkspace()}
          >
            <RefreshCw aria-hidden="true" /> Reload
          </Button>
        </div>
      ) : null}

      {query.isPending ? (
        <div
          aria-label="Loading related Alerts"
          className="alert-relation-skeleton"
        >
          <span />
          <span />
        </div>
      ) : null}
      {query.isError || !projection.canonical ? (
        <div className="alert-relation-panel__error">
          <FocusedError
            message={
              projection.canonical
                ? alertRelationProblem(query.error)
                : "The related Alert pages were not safe to combine."
            }
            title="Related Alerts unavailable"
          />
          <Button
            size="sm"
            variant="outline"
            onClick={() => void query.refetch()}
          >
            <RefreshCw aria-hidden="true" /> Retry relationships
          </Button>
        </div>
      ) : null}
      {!query.isPending &&
      !query.isError &&
      projection.canonical &&
      projection.items.length === 0 ? (
        <div className="alert-relation-panel__empty">
          <GitCompareArrows aria-hidden="true" />
          <h3>No Alert relationships recorded</h3>
          <p>
            Add evidence only when the duplicate or correlation is explicit.
          </p>
        </div>
      ) : null}
      {projection.canonical && projection.items.length > 0 ? (
        <ol className="alert-relation-list">
          {projection.items.map((relation) => (
            <AlertRelationCard
              canRetract={canMutate && relation.status === "active"}
              key={relation.id}
              onRetract={() => {
                attempt.current.current = null;
                setProblem(null);
                setNotice(null);
                setRetractionReason("");
                setRetracting(relation);
              }}
              relation={relation}
            />
          ))}
        </ol>
      ) : null}
      {query.hasNextPage ? (
        <Button
          disabled={query.isFetchingNextPage}
          onClick={() => void query.fetchNextPage()}
          size="sm"
          variant="outline"
        >
          <ArrowDown aria-hidden="true" />
          {query.isFetchingNextPage
            ? "Loading more…"
            : "Load more relationships"}
        </Button>
      ) : null}

      <Dialog
        open={retracting !== null}
        onOpenChange={(open) => !open && closeRetraction()}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Retract this Alert relationship?</DialogTitle>
            <DialogDescription>
              A terminal retraction will be appended. The original evidence is
              retained and this Alert pair cannot be related again.
            </DialogDescription>
          </DialogHeader>
          <form className="alert-relation-form" onSubmit={submitRetraction}>
            <div>
              <Label htmlFor="alert-relation-retraction-reason">Reason</Label>
              <Textarea
                autoFocus
                disabled={busy !== null}
                id="alert-relation-retraction-reason"
                maxLength={2000}
                onChange={(event) => {
                  setRetractionReason(event.currentTarget.value);
                  setProblem(null);
                  attempt.current.current = null;
                }}
                placeholder="Explain why this relationship is no longer valid"
                required
                value={retractionReason}
              />
              <small>Plain text, up to 2,000 UTF-8 bytes.</small>
            </div>
            {problem ? <p role="alert">{problem}</p> : null}
            <div className="alert-relation-form__actions">
              <Button
                disabled={busy !== null}
                onClick={closeRetraction}
                type="button"
                variant="ghost"
              >
                Cancel
              </Button>
              <Button
                disabled={!canMutate || !retractionDraftIsValid}
                type="submit"
                variant="destructive"
              >
                {busy === "retract" ? "Retracting…" : "Append retraction"}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>
    </section>
  );
}

function AlertRelationCard({
  canRetract,
  onRetract,
  relation,
}: {
  canRetract: boolean;
  onRetract: () => void;
  relation: AlertRelation;
}): React.JSX.Element {
  const direction =
    relation.relationType === "correlation"
      ? "Correlated Alerts"
      : relation.direction === "outgoing"
        ? "This Alert is a duplicate of"
        : "Duplicate of this Alert";
  return (
    <li>
      <article
        className={relation.status === "retracted" ? "is-retracted" : undefined}
      >
        <div className="alert-relation-card__rail" aria-hidden="true">
          <GitCompareArrows />
        </div>
        <div className="alert-relation-card__body">
          <header>
            <div>
              <small>{direction}</small>
              <Link to={`/alerts/${relation.relatedAlert.id}`}>
                <strong>{relation.relatedAlert.number}</strong>
                <span>{relation.relatedAlert.title}</span>
              </Link>
            </div>
            <div className="alert-relation-card__badges">
              <Badge
                variant={relation.status === "active" ? "secondary" : "outline"}
              >
                {humanizeKey(relation.status)}
              </Badge>
              <span className={severityTone(relation.relatedAlert.severity)}>
                {humanizeKey(relation.relatedAlert.severity)}
              </span>
            </div>
          </header>
          <dl>
            <div>
              <dt>Original reason</dt>
              <dd>{relation.reason}</dd>
            </div>
            <div>
              <dt>Recorded</dt>
              <dd>
                <TenantInstant value={relation.linkedAt} precision="second" />
              </dd>
            </div>
            <div>
              <dt>Related snapshot</dt>
              <dd>
                v{relation.relatedAlert.version} ·{" "}
                {humanizeKey(relation.relatedAlert.stateKey)}
              </dd>
            </div>
          </dl>
          {relation.retraction ? (
            <aside className="alert-relation-card__retraction">
              <RotateCcw aria-hidden="true" />
              <div>
                <strong>Retraction appended</strong>
                <p>{relation.retraction.reason}</p>
                <small>
                  <TenantInstant
                    value={relation.retraction.retractedAt}
                    precision="second"
                  />
                </small>
              </div>
            </aside>
          ) : null}
        </div>
        <div className="alert-relation-card__actions">
          <Button asChild size="sm" variant="ghost">
            <Link to={`/alerts/${relation.relatedAlert.id}`}>Open Alert</Link>
          </Button>
          {canRetract ? (
            <Button onClick={onRetract} size="sm" variant="outline">
              <RotateCcw aria-hidden="true" /> Retract
            </Button>
          ) : null}
        </div>
      </article>
    </li>
  );
}

export function flattenAlertRelationPages(
  pages: readonly AlertRelationPage[] | undefined,
): { canonical: boolean; items: readonly AlertRelation[] } {
  if (!pages) return { canonical: true, items: [] };
  const items: AlertRelation[] = [];
  const ids = new Set<string>();
  const pairs = new Set<string>();
  let previousId: string | undefined;
  for (const page of pages) {
    for (const item of page.items) {
      const pair = [item.sourceAlertId, item.targetAlertId]
        .toSorted()
        .join(":");
      if (
        ids.has(item.id) ||
        pairs.has(pair) ||
        (previousId !== undefined && previousId <= item.id)
      ) {
        return { canonical: false, items: [] };
      }
      ids.add(item.id);
      pairs.add(pair);
      previousId = item.id;
      items.push(item);
    }
  }
  return { canonical: true, items };
}

function safeNextCursor(
  page: AlertRelationPage,
  pages: readonly AlertRelationPage[],
): string | undefined {
  const cursor = page.nextCursor;
  return cursor !== undefined &&
    !pages.slice(0, -1).some((candidate) => candidate.nextCursor === cursor)
    ? cursor
    : undefined;
}

function isAbortError(error: unknown): boolean {
  return error instanceof DOMException && error.name === "AbortError";
}

function isReloadedAlertBoundary(
  value: ReloadedAlertBoundary | null,
): value is ReloadedAlertBoundary {
  return (
    value !== null &&
    Number.isSafeInteger(value.version) &&
    value.version >= 1 &&
    value.version <= 2_147_483_647 &&
    value.etag === `"v${value.version}"`
  );
}

function alertRelationProblem(error: unknown): string {
  if (error instanceof AlertRelationApiError) return error.message;
  return describeTicketingError(
    error,
    "The Alert relationship could not be updated from the current governed snapshots.",
  );
}
