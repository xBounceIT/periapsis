import {
  Alert,
  AlertDescription,
  AlertTitle,
} from "@periapsis/ui/components/ui/alert";
import { Badge } from "@periapsis/ui/components/ui/badge";
import { Button } from "@periapsis/ui/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@periapsis/ui/components/ui/card";
import { Input } from "@periapsis/ui/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@periapsis/ui/components/ui/select";
import { Textarea } from "@periapsis/ui/components/ui/textarea";
import {
  ArrowDown,
  CheckCircle2,
  CircleStop,
  History,
  Plus,
  RefreshCw,
  UserMinus,
  UserPlus,
  UsersRound,
} from "lucide-react";
import { useCallback, useEffect, useId, useRef, useState } from "react";

import { useSession } from "../auth/session-context";
import { useTenantAuthority } from "../auth/tenant-authority-context";
import { FocusedError } from "../components/focused-error";
import { FormField } from "../components/form-field";
import { ServerDenied } from "../components/server-denied";
import { readTextField } from "../lib/form-data";
import { currentInstant, parseRfc3339Instant } from "../lib/rfc3339-instant";
import { hasControlCharacters } from "../lib/text-validation";
import {
  describePhaseTwoError,
  PhaseTwoApiError,
  type OperatorTeamAssignmentEpochView,
  type OperatorTeamRosterEntryCreateInput,
  type OperatorTeamRosterEntryView,
  type TenantUserSummaryView,
  type VersionedView,
} from "../lib/phase-two-types";

type EpochListState =
  | { kind: "error"; message: string }
  | { kind: "forbidden" }
  | {
      items: readonly OperatorTeamAssignmentEpochView[];
      kind: "ready";
      nextCursor?: string;
    }
  | { kind: "loading" };

type UserInventoryState =
  | { kind: "error"; message: string }
  | { kind: "loading" }
  | {
      items: readonly TenantUserSummaryView[];
      kind: "ready";
      nextCursor?: string;
    };

interface EpochSelection {
  epochId: string;
  operatorTeamId: string;
  pairKey: string;
}

type OperatorTeamMutationKind = "add" | "end" | "revoke" | "start";

interface OperatorTeamMutationRequest {
  boundaryKey: string;
  generation: number;
  kind: OperatorTeamMutationKind;
  pairKey: string;
}

interface RosterPaginationRequest {
  boundaryKey: string;
  controller: AbortController;
  cursor: string;
  generation: number;
}

interface RosterInitialRequest {
  boundaryKey: string;
  controller: AbortController;
  generation: number;
}

type TenantTeamNotice =
  | { kind: "end"; teamName: string }
  | {
      kind: "start";
      state: OperatorTeamAssignmentEpochView["state"];
      teamName: string;
    };

const maximumRosterExpiryInstant = parseRfc3339Instant(
  "9999-12-31T23:59:59.999999Z",
);

export function TenantOperatorTeamsPage(): React.JSX.Element {
  const { api, clearSession, session } = useSession();
  const authority = useTenantAuthority();
  const tenantId = session.activeTenantId;
  const pairKey = authority.pairKey;
  const pairRef = useRef(pairKey);
  pairRef.current = pairKey;
  const canRead = authority.hasPermission("operator_team.read", "tenant");
  const canManage = authority.hasPermission("operator_team.manage", "tenant");
  const canEnd = canManage && authority.hasPermission("role.grant", "tenant");
  const canReadUsers = authority.hasPermission("user.read", "tenant");
  const canReadRoster =
    canReadUsers &&
    (canRead || authority.hasPermission("operator_team.read", "operator_team"));
  const canRevokeRoster =
    authority.hasPermission("role.grant", "tenant") &&
    authority.hasPermission("operator_team.roster.manage", "tenant");
  const canAddRoster = canReadUsers && canRevokeRoster;
  const startAllowedRef = useRef(false);
  const authorityRevisionRef = useRef(authority.revision);
  startAllowedRef.current =
    Boolean(tenantId) && authority.status === "ready" && canRead && canManage;
  authorityRevisionRef.current = authority.revision;
  const [listState, setListState] = useState<EpochListState>({
    kind: "loading",
  });
  const [listRevision, setListRevision] = useState(0);
  const [selection, setSelection] = useState<EpochSelection | null>(null);
  const [isLoadingMore, setIsLoadingMore] = useState(false);
  const [paginationError, setPaginationError] = useState<string | null>(null);
  const [isStarting, setIsStarting] = useState(false);
  const [startError, setStartError] = useState<string | null>(null);
  const [startReasonError, setStartReasonError] = useState<string | null>(null);
  const [notice, setNotice] = useState<TenantTeamNotice | null>(null);
  const activeMutationRef = useRef<OperatorTeamMutationRequest | null>(null);
  const coordinatorPairRef = useRef(pairKey);
  const observedExplicitRevisionRef = useRef(authority.explicitRevision);
  const startGenerationRef = useRef(0);
  const startRequestRef = useRef<OperatorTeamMutationRequest | null>(null);
  const paginationCursorsRef = useRef<Set<string>>(new Set());
  const paginationRequestRef = useRef<AbortController | null>(null);
  const id = useId();

  if (coordinatorPairRef.current !== pairKey) {
    coordinatorPairRef.current = pairKey;
    startRequestRef.current = null;
    startGenerationRef.current += 1;
    observedExplicitRevisionRef.current = authority.explicitRevision;
  }

  const requestAuthorityReload = useCallback(
    (request: OperatorTeamMutationRequest): void => {
      authority.requestMutationReload(request.pairKey, request);
    },
    [authority.requestMutationReload],
  );

  const registerMutation = useCallback(
    (request: OperatorTeamMutationRequest): boolean => {
      if (pairRef.current !== request.pairKey || activeMutationRef.current) {
        return false;
      }
      if (!authority.registerMutation(request.pairKey, request)) return false;
      activeMutationRef.current = request;
      return true;
    },
    [authority.registerMutation],
  );

  const detachMutation = useCallback(
    (request: OperatorTeamMutationRequest): void => {
      authority.detachMutation(request.pairKey, request);
      if (activeMutationRef.current === request) {
        activeMutationRef.current = null;
      }
    },
    [authority.detachMutation],
  );

  const settleMutation = useCallback(
    (request: OperatorTeamMutationRequest): void => {
      authority.settleMutation(request.pairKey, request);
      if (activeMutationRef.current === request) {
        activeMutationRef.current = null;
      }
    },
    [authority.settleMutation],
  );

  useEffect(() => {
    setSelection(null);
    setPaginationError(null);
    setIsLoadingMore(false);
    setIsStarting(false);
    setStartError(null);
    setStartReasonError(null);
    setNotice(null);
    paginationCursorsRef.current.clear();
  }, [pairKey]);

  useEffect(() => {
    if (authority.explicitRevision !== observedExplicitRevisionRef.current) {
      observedExplicitRevisionRef.current = authority.explicitRevision;
      authority.clearIdempotentPayloadBindings(
        pairKey,
        "operator-team-roster-add",
      );
      authority.clearIdempotentPayloadBindings(pairKey, "operator-team-start");
      startGenerationRef.current += 1;
      const request = startRequestRef.current;
      startRequestRef.current = null;
      if (request) detachMutation(request);
      setIsStarting(false);
      setStartError(null);
      setStartReasonError(null);
      setNotice(null);
    }

    const addBindingFailClosed =
      (authority.status === "ready" && !canAddRoster) ||
      authority.status === "error" ||
      authority.status === "forbidden" ||
      authority.status === "inactive";
    if (addBindingFailClosed) {
      authority.clearIdempotentPayloadBindings(
        pairKey,
        "operator-team-roster-add",
      );
    }
  }, [
    authority.clearIdempotentPayloadBindings,
    authority.explicitRevision,
    authority.status,
    canAddRoster,
    detachMutation,
    pairKey,
  ]);

  useEffect(() => {
    const finalStartFailClosed =
      (authority.status === "ready" && !startAllowedRef.current) ||
      authority.status === "error" ||
      authority.status === "forbidden" ||
      authority.status === "inactive";
    if (!finalStartFailClosed) return;
    startGenerationRef.current += 1;
    const request = startRequestRef.current;
    startRequestRef.current = null;
    if (request) detachMutation(request);
    setIsStarting(false);
    setStartError(null);
    setStartReasonError(null);
    setNotice(null);
    authority.clearIdempotentPayloadBindings(pairKey, "operator-team-start");
  }, [
    authority.clearIdempotentPayloadBindings,
    authority.status,
    canManage,
    canRead,
    detachMutation,
    pairKey,
    tenantId,
  ]);

  useEffect(() => {
    const effectPair = pairKey;
    return () => {
      paginationRequestRef.current?.abort();
      const request = activeMutationRef.current;
      if (request?.pairKey === effectPair) detachMutation(request);
      if (startRequestRef.current?.pairKey === effectPair) {
        startRequestRef.current = null;
        startGenerationRef.current += 1;
      }
    };
  }, [detachMutation, pairKey]);

  useEffect(() => {
    setPaginationError(null);
    paginationRequestRef.current?.abort();
    paginationRequestRef.current = null;
    setIsLoadingMore(false);
    if (!tenantId || authority.status !== "ready" || !canRead) {
      setListState(
        authority.status === "ready" && tenantId && !canRead
          ? { kind: "forbidden" }
          : { kind: "loading" },
      );
      return undefined;
    }
    const controller = new AbortController();
    const requestedPair = pairKey;
    paginationCursorsRef.current.clear();
    setListState({ kind: "loading" });
    void api
      .listTenantOperatorTeamAssignmentEpochs(tenantId, {
        includeEnded: true,
        signal: controller.signal,
      })
      .then((page) => {
        if (controller.signal.aborted || pairRef.current !== requestedPair)
          return;
        const items = mergeAssignmentEpochs([], page.items, tenantId);
        if (page.nextCursor) paginationCursorsRef.current.add(page.nextCursor);
        setListState({
          items,
          kind: "ready",
          ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
        });
        const preferred =
          items.find((epoch) => epoch.state === "active") ?? items[0];
        if (preferred) {
          setSelection({
            epochId: preferred.epochId,
            operatorTeamId: preferred.operatorTeam.id,
            pairKey: requestedPair,
          });
        }
      })
      .catch((caught: unknown) => {
        if (
          controller.signal.aborted ||
          pairRef.current !== requestedPair ||
          isAbortError(caught)
        )
          return;
        if (caught instanceof PhaseTwoApiError && caught.status === 401) {
          clearSession(session.id);
          return;
        }
        setListState(
          caught instanceof PhaseTwoApiError && caught.status === 403
            ? { kind: "forbidden" }
            : {
                kind: "error",
                message: describePhaseTwoError(
                  caught,
                  "The tenant operator-team epoch inventory could not be loaded.",
                ),
              },
        );
      });
    return () => controller.abort();
  }, [
    api,
    authority.status,
    canRead,
    clearSession,
    listRevision,
    pairKey,
    session.id,
    tenantId,
  ]);

  async function loadMore(): Promise<void> {
    if (
      !tenantId ||
      listState.kind !== "ready" ||
      !listState.nextCursor ||
      isLoadingMore ||
      paginationRequestRef.current
    ) {
      return;
    }
    const cursor = listState.nextCursor;
    const requestedPair = pairKey;
    const controller = new AbortController();
    paginationRequestRef.current = controller;
    setIsLoadingMore(true);
    setPaginationError(null);
    try {
      const page = await api.listTenantOperatorTeamAssignmentEpochs(tenantId, {
        after: cursor,
        includeEnded: true,
        signal: controller.signal,
      });
      if (controller.signal.aborted || pairRef.current !== requestedPair)
        return;
      if (page.nextCursor === cursor) {
        throw new Error("The assignment-epoch cursor did not advance.");
      }
      if (
        page.nextCursor &&
        paginationCursorsRef.current.has(page.nextCursor)
      ) {
        throw new Error("The assignment-epoch cursor entered a cycle.");
      }
      if (page.nextCursor) paginationCursorsRef.current.add(page.nextCursor);
      setListState((current) =>
        current.kind === "ready" && current.nextCursor === cursor
          ? {
              items: mergeAssignmentEpochs(current.items, page.items, tenantId),
              kind: "ready",
              ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
            }
          : current,
      );
    } catch (caught) {
      if (
        controller.signal.aborted ||
        pairRef.current !== requestedPair ||
        isAbortError(caught)
      )
        return;
      if (caught instanceof PhaseTwoApiError && caught.status === 401) {
        clearSession(session.id);
        return;
      }
      setPaginationError(
        describePhaseTwoError(
          caught,
          "The next assignment-epoch page could not be loaded.",
        ),
      );
    } finally {
      if (paginationRequestRef.current === controller) {
        paginationRequestRef.current = null;
      }
      if (pairRef.current === requestedPair) setIsLoadingMore(false);
    }
  }

  async function startEpoch(
    event: React.FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault();
    if (!tenantId || !startAllowedRef.current) return;
    const form = event.currentTarget;
    const data = new FormData(form);
    const operatorTeamId = readTextField(data, "operatorTeamId").trim();
    const reason = readTextField(data, "reason").trim();
    const reasonError = administrativeReasonError(reason);
    if (reasonError) {
      setStartReasonError(reasonError);
      return;
    }
    setStartReasonError(null);
    const input = { reason };
    const requestedPair = pairKey;
    const requestedAuthorityRevision = authority.revision;
    const requestedGeneration = startGenerationRef.current + 1;
    const request: OperatorTeamMutationRequest = {
      boundaryKey: JSON.stringify([
        requestedPair,
        tenantId,
        requestedAuthorityRevision,
      ]),
      generation: requestedGeneration,
      kind: "start",
      pairKey: requestedPair,
    };
    if (!registerMutation(request)) return;
    startGenerationRef.current = requestedGeneration;
    startRequestRef.current = request;
    setStartError(null);
    setNotice(null);
    setIsStarting(true);
    const bindingPayload = {
      input,
      operatorTeamId,
      tenantId,
    };
    const idempotencyKey = authority.bindIdempotentPayload(
      requestedPair,
      "operator-team-start",
      operatorTeamStartIdentityKey(tenantId),
      request,
      bindingPayload,
    );
    if (!idempotencyKey) {
      startRequestRef.current = null;
      settleMutation(request);
      setIsStarting(false);
      return;
    }
    try {
      const created = await api.startOperatorTeamAssignmentEpoch(
        session.csrfToken,
        tenantId,
        operatorTeamId,
        idempotencyKey,
        input,
      );
      requestAuthorityReload(request);
      authority.releaseIdempotentPayload(
        requestedPair,
        "operator-team-start",
        operatorTeamStartIdentityKey(tenantId),
        request,
        idempotencyKey,
        bindingPayload,
      );
      if (
        pairRef.current !== requestedPair ||
        authorityRevisionRef.current !== requestedAuthorityRevision ||
        !startAllowedRef.current ||
        startGenerationRef.current !== requestedGeneration ||
        startRequestRef.current !== request
      )
        return;
      form.reset();
      setListState((current) =>
        current.kind === "ready"
          ? {
              ...current,
              items: mergeAssignmentEpochs(
                current.items,
                [created.value],
                tenantId,
              ),
            }
          : current,
      );
      setSelection({
        epochId: created.value.epochId,
        operatorTeamId: created.value.operatorTeam.id,
        pairKey: requestedPair,
      });
      setNotice({
        kind: "start",
        state: created.value.state,
        teamName: created.value.operatorTeam.name,
      });
    } catch (caught) {
      if (
        pairRef.current !== requestedPair ||
        authorityRevisionRef.current !== requestedAuthorityRevision ||
        !startAllowedRef.current ||
        startGenerationRef.current !== requestedGeneration ||
        startRequestRef.current !== request
      )
        return;
      if (caught instanceof PhaseTwoApiError && caught.status === 401) {
        clearSession(session.id);
        return;
      }
      setStartError(
        describePhaseTwoError(
          caught,
          "The assignment epoch was not started. The same payload can be retried safely.",
        ),
      );
    } finally {
      const current =
        pairRef.current === requestedPair &&
        authorityRevisionRef.current === requestedAuthorityRevision &&
        startAllowedRef.current &&
        startGenerationRef.current === requestedGeneration &&
        startRequestRef.current === request;
      if (startRequestRef.current === request) startRequestRef.current = null;
      settleMutation(request);
      if (current) setIsStarting(false);
    }
  }

  if (!tenantId) {
    return (
      <div className="content content--narrow">
        <section className="page-heading">
          <div>
            <p className="section-label">Tenant operations</p>
            <h1>Select a tenant to inspect operator teams.</h1>
            <p>
              The tenant switcher establishes the explicit authorization and RLS
              context.
            </p>
          </div>
        </section>
      </div>
    );
  }
  if (authority.status === "forbidden" || listState.kind === "forbidden") {
    return <ServerDenied resource="operator-team assignment epochs" />;
  }
  if (authority.status === "error") {
    return (
      <div className="content content--narrow">
        <FocusedError
          message={authority.message ?? "Tenant authority could not be loaded."}
        />
        <Button type="button" variant="outline" onClick={authority.reload}>
          <RefreshCw aria-hidden="true" /> Reload tenant authority
        </Button>
      </div>
    );
  }
  if (authority.status !== "ready") {
    return <TenantOperatorTeamSkeleton />;
  }
  if (!canRead) {
    return <ServerDenied resource="tenant operator-team inventory" />;
  }

  const selected = selection?.pairKey === pairKey ? selection : null;
  const mutationPending = authority.hasPendingMutation(pairKey);

  return (
    <div className="content operator-team-page tenant-operator-team-page">
      <section className="page-heading" aria-labelledby="tenant-team-title">
        <div>
          <p className="section-label">Tenant administration</p>
          <h1 id="tenant-team-title">Assignment epochs & roster</h1>
          <p>
            Each assignment is immutable history. Ending and later reassigning a
            team creates a fresh epoch; old roster edges never revive.
          </p>
        </div>
        <Badge variant="outline">
          <History aria-hidden="true" /> Exact-epoch authority
        </Badge>
      </section>

      {notice ? (
        <Alert
          className={
            notice.kind === "end" || notice.state === "active"
              ? "success-alert"
              : undefined
          }
        >
          {notice.kind === "start" && notice.state === "ended" ? (
            <History aria-hidden="true" />
          ) : (
            <CheckCircle2 aria-hidden="true" />
          )}
          <AlertTitle>
            {notice.kind === "start" && notice.state === "ended"
              ? "Assignment epoch is historical"
              : "Tenant team updated"}
          </AlertTitle>
          <AlertDescription>
            {notice.kind === "end"
              ? `${notice.teamName} ended this epoch. Its roster remains history only.`
              : notice.state === "ended"
                ? `${notice.teamName} returned an ended historical epoch. It provides no current tenant coverage.`
                : `${notice.teamName} started a new immutable epoch.`}
          </AlertDescription>
        </Alert>
      ) : null}

      {canManage ? (
        <Card className="epoch-start-card">
          <CardHeader>
            <CardTitle>Start assignment epoch</CardTitle>
            <CardDescription>
              Enter a global team UUID. The server rejects archived teams and
              duplicate active assignments.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form className="epoch-start-form" onSubmit={startEpoch}>
              {startError ? <FocusedError message={startError} /> : null}
              <FormField htmlFor={`${id}-team-id`} label="Operator team ID">
                <Input
                  id={`${id}-team-id`}
                  name="operatorTeamId"
                  required
                  minLength={36}
                  maxLength={36}
                  pattern="[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
                  disabled={isStarting || mutationPending}
                  autoCapitalize="none"
                  autoCorrect="off"
                />
              </FormField>
              <FormField
                htmlFor={`${id}-start-reason`}
                label="Assignment reason"
                {...(startReasonError ? { error: startReasonError } : {})}
              >
                <Input
                  id={`${id}-start-reason`}
                  name="reason"
                  required
                  minLength={1}
                  maxLength={500}
                  disabled={isStarting || mutationPending}
                  aria-invalid={startReasonError ? true : undefined}
                  aria-describedby={
                    startReasonError ? `${id}-start-reason-error` : undefined
                  }
                  onChange={(event) => {
                    if (startReasonError) {
                      setStartReasonError(
                        administrativeReasonError(event.target.value),
                      );
                    }
                  }}
                />
              </FormField>
              <Button
                type="submit"
                disabled={
                  isStarting || mutationPending || Boolean(startReasonError)
                }
              >
                <Plus aria-hidden="true" />
                {isStarting ? "Starting epoch…" : "Start assignment epoch"}
              </Button>
            </form>
          </CardContent>
        </Card>
      ) : null}

      {listState.kind === "error" ? (
        <div className="operator-team-list-error">
          <FocusedError message={listState.message} />
          <Button
            type="button"
            variant="outline"
            onClick={() => setListRevision((value) => value + 1)}
          >
            <RefreshCw aria-hidden="true" /> Retry epoch inventory
          </Button>
        </div>
      ) : null}
      {listState.kind === "loading" ? <EpochRailSkeleton /> : null}
      {paginationError ? (
        <FocusedError
          message={paginationError}
          title="More epochs could not be loaded"
        />
      ) : null}
      {listState.kind === "ready" && listState.items.length === 0 ? (
        <div className="operator-team-empty">
          <UsersRound aria-hidden="true" />
          <h3>No assignment history</h3>
          <p>
            Start an epoch when this tenant is ready to receive work from a
            global team.
          </p>
        </div>
      ) : null}
      {listState.kind === "ready" && listState.items.length > 0 ? (
        <div className="epoch-workbench">
          <aside
            className="epoch-rail-panel"
            aria-labelledby="epoch-rail-title"
          >
            <div className="operator-team-section-heading">
              <div>
                <p className="section-label">Immutable handoffs</p>
                <h2 id="epoch-rail-title">Epoch rail</h2>
              </div>
              <Badge variant="outline">{listState.items.length} loaded</Badge>
            </div>
            <ol className="epoch-rail">
              {listState.items.map((epoch) => {
                const active = epoch.state === "active";
                const selectedEpoch = selected?.epochId === epoch.epochId;
                return (
                  <li key={epoch.epochId} data-state={epoch.state}>
                    <button
                      type="button"
                      className="epoch-node"
                      aria-current={selectedEpoch ? "true" : undefined}
                      aria-label={`Open ${epoch.operatorTeam.name} epoch ${shortId(epoch.epochId)}, ${epoch.state}`}
                      onClick={() =>
                        setSelection({
                          epochId: epoch.epochId,
                          operatorTeamId: epoch.operatorTeam.id,
                          pairKey,
                        })
                      }
                    >
                      <span className="epoch-node__marker" aria-hidden="true" />
                      <span className="epoch-node__copy">
                        <span>
                          <strong>{epoch.operatorTeam.name}</strong>
                          <Badge variant={active ? "secondary" : "outline"}>
                            {epoch.state}
                          </Badge>
                        </span>
                        <small>
                          {epoch.operatorTeam.key} · epoch{" "}
                          {shortId(epoch.epochId)}
                        </small>
                        <time dateTime={epoch.startedAt}>
                          Started {formatDateTime(epoch.startedAt)}
                        </time>
                        {epoch.endedAt ? (
                          <time dateTime={epoch.endedAt}>
                            Ended {formatDateTime(epoch.endedAt)}
                          </time>
                        ) : null}
                      </span>
                    </button>
                  </li>
                );
              })}
            </ol>
            {listState.nextCursor ? (
              <Button
                type="button"
                variant="outline"
                disabled={isLoadingMore}
                onClick={() => void loadMore()}
              >
                <ArrowDown aria-hidden="true" />
                {isLoadingMore ? "Loading epochs…" : "Load more epochs"}
              </Button>
            ) : null}
          </aside>

          <section className="epoch-detail-panel" aria-live="polite">
            {selected ? (
              <EpochDetail
                key={`${pairKey}:${selected.operatorTeamId}:${selected.epochId}`}
                addBindingIdentityKey={epochMutationIdentityKey(
                  tenantId,
                  selected.operatorTeamId,
                  selected.epochId,
                )}
                canAddRoster={canAddRoster}
                canEnd={canEnd}
                canReadRoster={canReadRoster}
                canRevokeRoster={canRevokeRoster}
                epochId={selected.epochId}
                operatorTeamId={selected.operatorTeamId}
                pairKey={pairKey}
                parentMutationPending={mutationPending}
                tenantId={tenantId}
                onAuthorityChanged={requestAuthorityReload}
                onEpochEnded={(ended) => {
                  setListState((current) =>
                    current.kind === "ready"
                      ? {
                          ...current,
                          items: mergeAssignmentEpochs(
                            current.items,
                            [ended],
                            tenantId,
                          ),
                        }
                      : current,
                  );
                  setNotice({
                    kind: "end",
                    teamName: ended.operatorTeam.name,
                  });
                }}
                onMutationSettled={settleMutation}
                onMutationDetached={detachMutation}
                onMutationStarted={registerMutation}
              />
            ) : null}
          </section>
        </div>
      ) : null}
    </div>
  );
}

function EpochDetail({
  addBindingIdentityKey,
  canAddRoster,
  canEnd,
  canReadRoster,
  canRevokeRoster,
  epochId,
  onAuthorityChanged,
  onEpochEnded,
  onMutationDetached,
  onMutationSettled,
  onMutationStarted,
  operatorTeamId,
  pairKey,
  parentMutationPending,
  tenantId,
}: {
  addBindingIdentityKey: string;
  canAddRoster: boolean;
  canEnd: boolean;
  canReadRoster: boolean;
  canRevokeRoster: boolean;
  epochId: string;
  onAuthorityChanged: (request: OperatorTeamMutationRequest) => void;
  onEpochEnded: (epoch: OperatorTeamAssignmentEpochView) => void;
  onMutationDetached: (request: OperatorTeamMutationRequest) => void;
  onMutationSettled: (request: OperatorTeamMutationRequest) => void;
  onMutationStarted: (request: OperatorTeamMutationRequest) => boolean;
  operatorTeamId: string;
  pairKey: string;
  parentMutationPending: boolean;
  tenantId: string;
}): React.JSX.Element {
  const { api, clearSession, session } = useSession();
  const authority = useTenantAuthority();
  const [epoch, setEpoch] = useState<
    | { kind: "error"; message: string }
    | { kind: "loading" }
    | {
        kind: "ready";
        resource: VersionedView<OperatorTeamAssignmentEpochView>;
      }
  >({ kind: "loading" });
  const [roster, setRoster] = useState<
    | { kind: "error"; message: string }
    | { kind: "loading" }
    | {
        kind: "ready";
        items: readonly OperatorTeamRosterEntryView[];
        nextCursor?: string;
      }
  >({ kind: "loading" });
  const [users, setUsers] = useState<UserInventoryState>({ kind: "loading" });
  const [userRevision, setUserRevision] = useState(0);
  const [isLoadingMoreUsers, setIsLoadingMoreUsers] = useState(false);
  const [userPaginationError, setUserPaginationError] = useState<string | null>(
    null,
  );
  const [revision, setRevision] = useState(0);
  const [rosterRevision, setRosterRevision] = useState(0);
  const [isLoadingMore, setIsLoadingMore] = useState(false);
  const [paginationError, setPaginationError] = useState<string | null>(null);
  const [endReason, setEndReason] = useState("");
  const [endReasonError, setEndReasonError] = useState<string | null>(null);
  const [endError, setEndError] = useState<string | null>(null);
  const [isEnding, setIsEnding] = useState(false);
  const [endCommitted, setEndCommitted] = useState(false);
  const [memberId, setMemberId] = useState("");
  const [addReason, setAddReason] = useState("");
  const [addReasonError, setAddReasonError] = useState<string | null>(null);
  const [expiresAt, setExpiresAt] = useState("");
  const [expiresAtError, setExpiresAtError] = useState<string | null>(null);
  const [addError, setAddError] = useState<string | null>(null);
  const [isAdding, setIsAdding] = useState(false);
  const [revokeEntryId, setRevokeEntryId] = useState<string | null>(null);
  const [revokeReason, setRevokeReason] = useState("");
  const [revokeReasonError, setRevokeReasonError] = useState<string | null>(
    null,
  );
  const [revokeError, setRevokeError] = useState<string | null>(null);
  const [isRevoking, setIsRevoking] = useState(false);
  const mountedRef = useRef(false);
  const mutationBoundaryRef = useRef("");
  const mutationGenerationRef = useRef(0);
  const mutationRequestRef = useRef<OperatorTeamMutationRequest | null>(null);
  const rosterCursorsRef = useRef<Set<string>>(new Set());
  const rosterInitialGenerationRef = useRef(0);
  const rosterInitialRequestRef = useRef<RosterInitialRequest | null>(null);
  const rosterPaginationGenerationRef = useRef(0);
  const rosterPaginationRequestRef = useRef<RosterPaginationRequest | null>(
    null,
  );
  const userCursorsRef = useRef<Set<string>>(new Set());
  const userRequestRef = useRef<AbortController | null>(null);
  const canAddRosterRef = useRef(canAddRoster);
  const canEndRef = useRef(canEnd);
  const revokeAllowedRef = useRef(false);
  const pairRef = useRef(pairKey);
  pairRef.current = pairKey;
  const rosterBoundaryKey = JSON.stringify([
    pairKey,
    tenantId,
    operatorTeamId,
    epochId,
  ]);
  const rosterBoundaryRef = useRef(rosterBoundaryKey);
  rosterBoundaryRef.current = rosterBoundaryKey;
  const id = useId();

  const invalidateRosterPagination = useCallback((): void => {
    rosterPaginationGenerationRef.current += 1;
    const request = rosterPaginationRequestRef.current;
    rosterPaginationRequestRef.current = null;
    request?.controller.abort();
    if (mountedRef.current) setIsLoadingMore(false);
  }, []);

  const invalidateRosterInitialRequest = useCallback((): boolean => {
    rosterInitialGenerationRef.current += 1;
    const request = rosterInitialRequestRef.current;
    rosterInitialRequestRef.current = null;
    request?.controller.abort();
    return request !== null;
  }, []);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      invalidateRosterInitialRequest();
      invalidateRosterPagination();
      userRequestRef.current?.abort();
      const request = mutationRequestRef.current;
      mutationRequestRef.current = null;
      if (request) onMutationDetached(request);
    };
  }, [
    invalidateRosterInitialRequest,
    invalidateRosterPagination,
    onMutationDetached,
  ]);

  const exactEpochState =
    epoch.kind === "ready" ? epoch.resource.value.state : undefined;
  const rosterMutationsOpen = exactEpochState === "active" && !endCommitted;
  const mutationBoundaryKey = JSON.stringify([
    pairKey,
    tenantId,
    operatorTeamId,
    epochId,
    exactEpochState ?? null,
    canAddRoster,
    canEnd,
    canRevokeRoster,
  ]);
  if (mutationBoundaryRef.current !== mutationBoundaryKey) {
    mutationBoundaryRef.current = mutationBoundaryKey;
    mutationGenerationRef.current += 1;
  }
  canAddRosterRef.current = canAddRoster && rosterMutationsOpen;
  canEndRef.current = canEnd && rosterMutationsOpen;
  revokeAllowedRef.current = canRevokeRoster && rosterMutationsOpen;
  const mutationPending =
    parentMutationPending || isAdding || isEnding || isRevoking;

  useEffect(() => {
    if (mutationBoundaryRef.current !== mutationBoundaryKey) return;
    invalidateRosterPagination();
    const request = mutationRequestRef.current;
    if (request && request.generation !== mutationGenerationRef.current) {
      mutationRequestRef.current = null;
      onMutationDetached(request);
    }
    if (mutationRequestRef.current) return;
    setIsAdding(false);
    setIsEnding(false);
    setIsRevoking(false);
    setAddError(null);
    setAddReasonError(null);
    setEndError(null);
    setEndReasonError(null);
    setExpiresAtError(null);
    setRevokeError(null);
    setRevokeReasonError(null);
  }, [invalidateRosterPagination, mutationBoundaryKey, onMutationDetached]);

  function mutationAllowed(kind: OperatorTeamMutationKind): boolean {
    if (kind === "add") return canAddRosterRef.current;
    if (kind === "end") return canEndRef.current;
    return kind === "revoke" && revokeAllowedRef.current;
  }

  function beginMutation(
    kind: OperatorTeamMutationKind,
  ): OperatorTeamMutationRequest | null {
    if (mutationRequestRef.current || !mutationAllowed(kind)) return null;
    const request: OperatorTeamMutationRequest = {
      boundaryKey: mutationBoundaryRef.current,
      generation: mutationGenerationRef.current,
      kind,
      pairKey,
    };
    if (!onMutationStarted(request)) return null;
    mutationRequestRef.current = request;
    invalidateRosterPagination();
    return request;
  }

  function mutationIsCurrent(request: OperatorTeamMutationRequest): boolean {
    return (
      mountedRef.current &&
      mutationRequestRef.current === request &&
      mutationBoundaryRef.current === request.boundaryKey &&
      mutationGenerationRef.current === request.generation
    );
  }

  function finishMutation(request: OperatorTeamMutationRequest): void {
    const current = mutationIsCurrent(request);
    if (mutationRequestRef.current === request) {
      mutationRequestRef.current = null;
    }
    onMutationSettled(request);
    if (!current) return;
    if (request.kind === "add") setIsAdding(false);
    else if (request.kind === "end") setIsEnding(false);
    else setIsRevoking(false);
  }

  useEffect(() => {
    const controller = new AbortController();
    const expectedPair = pairKey;
    setEpoch({ kind: "loading" });
    void api
      .getOperatorTeamAssignmentEpoch(
        tenantId,
        operatorTeamId,
        epochId,
        controller.signal,
      )
      .then((resource) => {
        if (controller.signal.aborted || pairRef.current !== expectedPair)
          return;
        setEpoch({ kind: "ready", resource });
        setEndError(null);
      })
      .catch((caught: unknown) => {
        if (controller.signal.aborted || isAbortError(caught)) return;
        if (caught instanceof PhaseTwoApiError && caught.status === 401) {
          clearSession(session.id);
          return;
        }
        setEpoch({
          kind: "error",
          message: describePhaseTwoError(
            caught,
            "The exact assignment epoch could not be loaded.",
          ),
        });
      });
    return () => controller.abort();
  }, [
    api,
    clearSession,
    epochId,
    operatorTeamId,
    pairKey,
    revision,
    session.id,
    tenantId,
  ]);

  useEffect(() => {
    invalidateRosterInitialRequest();
    invalidateRosterPagination();
    setPaginationError(null);
    if (!canReadRoster) {
      setRoster({
        kind: "error",
        message: "Roster visibility also requires tenant user.read authority.",
      });
      return undefined;
    }
    const controller = new AbortController();
    const expectedPair = pairKey;
    const expectedBoundary = rosterBoundaryKey;
    const request: RosterInitialRequest = {
      boundaryKey: expectedBoundary,
      controller,
      generation: rosterInitialGenerationRef.current,
    };
    rosterInitialRequestRef.current = request;
    rosterCursorsRef.current.clear();
    setRoster({ kind: "loading" });
    void api
      .listOperatorTeamRosterEntries(tenantId, operatorTeamId, epochId, {
        includeRevoked: true,
        signal: controller.signal,
      })
      .then((page) => {
        if (!rosterInitialRequestIsCurrent(request, expectedPair)) return;
        if (page.nextCursor) rosterCursorsRef.current.add(page.nextCursor);
        setRoster({
          items: page.items,
          kind: "ready",
          ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
        });
        setRevokeError(null);
      })
      .catch((caught: unknown) => {
        if (
          !rosterInitialRequestIsCurrent(request, expectedPair) ||
          isAbortError(caught)
        )
          return;
        if (caught instanceof PhaseTwoApiError && caught.status === 401) {
          clearSession(session.id);
          return;
        }
        setRoster({
          kind: "error",
          message: describePhaseTwoError(
            caught,
            "The exact-epoch roster could not be loaded.",
          ),
        });
      })
      .finally(() => {
        if (rosterInitialRequestRef.current === request) {
          rosterInitialRequestRef.current = null;
        }
      });
    return () => {
      controller.abort();
      if (rosterInitialRequestRef.current === request) {
        rosterInitialRequestRef.current = null;
      }
    };
  }, [
    api,
    canReadRoster,
    clearSession,
    epochId,
    invalidateRosterInitialRequest,
    invalidateRosterPagination,
    operatorTeamId,
    pairKey,
    rosterBoundaryKey,
    rosterRevision,
    session.id,
    tenantId,
  ]);

  useEffect(() => {
    userRequestRef.current?.abort();
    userRequestRef.current = null;
    userCursorsRef.current.clear();
    setIsLoadingMoreUsers(false);
    setUserPaginationError(null);
    if (!canAddRoster || !rosterMutationsOpen) {
      setUsers({ kind: "loading" });
      return undefined;
    }

    const controller = new AbortController();
    const expectedPair = pairKey;
    userRequestRef.current = controller;
    setUsers({ kind: "loading" });
    void api
      .listTenantUsers(tenantId, undefined, controller.signal)
      .then((page) => {
        if (controller.signal.aborted || pairRef.current !== expectedPair)
          return;
        assertTenantUsers(page.items, tenantId);
        if (page.nextCursor) userCursorsRef.current.add(page.nextCursor);
        setUsers({
          items: page.items,
          kind: "ready",
          ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
        });
      })
      .catch((caught: unknown) => {
        if (
          controller.signal.aborted ||
          pairRef.current !== expectedPair ||
          isAbortError(caught)
        ) {
          return;
        }
        if (caught instanceof PhaseTwoApiError && caught.status === 401) {
          clearSession(session.id);
          return;
        }
        setUsers({
          kind: "error",
          message: describePhaseTwoError(
            caught,
            "The tenant-member picker could not be loaded.",
          ),
        });
      })
      .finally(() => {
        if (userRequestRef.current === controller) {
          userRequestRef.current = null;
        }
      });
    return () => controller.abort();
  }, [
    api,
    canAddRoster,
    clearSession,
    pairKey,
    rosterMutationsOpen,
    session.id,
    tenantId,
    userRevision,
  ]);

  useEffect(() => {
    if (canAddRoster && exactEpochState !== "ended" && !endCommitted) return;
    setMemberId("");
    setAddReason("");
    setExpiresAt("");
    setAddError(null);
    setAddReasonError(null);
    setExpiresAtError(null);
    authority.clearIdempotentPayloadBindings(
      pairKey,
      "operator-team-roster-add",
      addBindingIdentityKey,
    );
  }, [
    addBindingIdentityKey,
    authority.clearIdempotentPayloadBindings,
    canAddRoster,
    endCommitted,
    exactEpochState,
    pairKey,
  ]);

  useEffect(() => {
    if (!revokeEntryId) return;
    const entry =
      roster.kind === "ready"
        ? roster.items.find((item) => item.id === revokeEntryId)
        : undefined;
    if (
      canRevokeRoster &&
      rosterMutationsOpen &&
      entry?.state === "active" &&
      entry.managedByOperatorTeamApi
    ) {
      return;
    }
    setRevokeEntryId(null);
    setRevokeReason("");
    setRevokeError(null);
    setRevokeReasonError(null);
  }, [canRevokeRoster, revokeEntryId, roster, rosterMutationsOpen]);

  async function endEpoch(): Promise<void> {
    if (epoch.kind !== "ready") return;
    const reason = endReason.trim();
    const reasonError = administrativeReasonError(reason);
    if (reasonError) {
      setEndReasonError(reasonError);
      return;
    }
    setEndReasonError(null);
    const request = beginMutation("end");
    if (!request) return;
    let mutationCommitted = false;
    setEndError(null);
    setIsEnding(true);
    try {
      await api.endOperatorTeamAssignmentEpoch(
        session.csrfToken,
        tenantId,
        operatorTeamId,
        epochId,
        epoch.resource.etag,
        { reason },
      );
      mutationCommitted = true;
      invalidateRosterInitialRequest();
      invalidateRosterPagination();
      onAuthorityChanged(request);
      if (!mutationIsCurrent(request)) return;
      setEndCommitted(true);
      setRosterRevision((value) => value + 1);
      const current = await api.getOperatorTeamAssignmentEpoch(
        tenantId,
        operatorTeamId,
        epochId,
      );
      if (!mutationIsCurrent(request)) return;
      setEpoch({ kind: "ready", resource: current });
      onEpochEnded(current.value);
    } catch (caught) {
      if (!mutationIsCurrent(request)) return;
      if (caught instanceof PhaseTwoApiError && caught.status === 401) {
        clearSession(session.id);
        return;
      }
      setEndError(
        mutationCommitted
          ? "The epoch ended, but its current representation could not be reloaded. Reload before any further roster action."
          : describePhaseTwoError(
              caught,
              "The assignment epoch was not ended.",
            ),
      );
    } finally {
      finishMutation(request);
    }
  }

  async function addRosterEntry(
    event: React.FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault();
    const reason = addReason.trim();
    const normalizedExpiresAt = expiresAt.trim();
    const reasonError = administrativeReasonError(reason);
    const input: OperatorTeamRosterEntryCreateInput = {
      membershipId: memberId,
      reason,
      ...(normalizedExpiresAt ? { expiresAt: normalizedExpiresAt } : {}),
    };
    const bindingPayload = {
      assignmentEpochId: epochId,
      input,
      operatorTeamId,
      tenantId,
    };
    const boundReplay = authority.isIdempotentPayloadBound(
      pairKey,
      "operator-team-roster-add",
      addBindingIdentityKey,
      bindingPayload,
    );
    const expiryError = rosterExpiryError(normalizedExpiresAt, boundReplay);
    setAddReasonError(reasonError);
    setExpiresAtError(expiryError);
    if (reasonError || expiryError) return;
    const request = beginMutation("add");
    if (!request) return;
    const idempotencyKey = authority.bindIdempotentPayload(
      pairKey,
      "operator-team-roster-add",
      addBindingIdentityKey,
      request,
      bindingPayload,
    );
    if (!idempotencyKey) {
      finishMutation(request);
      return;
    }
    setAddError(null);
    setIsAdding(true);
    try {
      const created = await api.addOperatorTeamRosterEntry(
        session.csrfToken,
        tenantId,
        operatorTeamId,
        epochId,
        idempotencyKey,
        input,
      );
      const initialRosterInvalidated = invalidateRosterInitialRequest();
      invalidateRosterPagination();
      onAuthorityChanged(request);
      authority.releaseIdempotentPayload(
        pairKey,
        "operator-team-roster-add",
        addBindingIdentityKey,
        request,
        idempotencyKey,
        bindingPayload,
      );
      if (!mutationIsCurrent(request)) return;
      if (initialRosterInvalidated) {
        setRosterRevision((value) => value + 1);
      } else {
        setRoster((current) =>
          current.kind === "ready"
            ? {
                ...current,
                items: mergeRosterEntries(current.items, [created.value]),
              }
            : current,
        );
      }
      setMemberId("");
      setAddReason("");
      setExpiresAt("");
      setAddReasonError(null);
      setExpiresAtError(null);
    } catch (caught) {
      if (!mutationIsCurrent(request)) return;
      if (caught instanceof PhaseTwoApiError && caught.status === 401) {
        clearSession(session.id);
        return;
      }
      setAddError(
        describePhaseTwoError(
          caught,
          "The roster edge was not added. The same exact-epoch payload can be retried safely.",
        ),
      );
    } finally {
      finishMutation(request);
    }
  }

  async function revokeRosterEntry(): Promise<void> {
    if (!revokeEntryId || roster.kind !== "ready") return;
    const entry = roster.items.find((item) => item.id === revokeEntryId);
    if (!entry || entry.state !== "active" || !entry.managedByOperatorTeamApi)
      return;
    const reason = revokeReason.trim();
    const reasonError = administrativeReasonError(reason);
    if (reasonError) {
      setRevokeReasonError(reasonError);
      return;
    }
    setRevokeReasonError(null);
    const request = beginMutation("revoke");
    if (!request) return;
    setRevokeError(null);
    setIsRevoking(true);
    try {
      await api.revokeOperatorTeamRosterEntry(
        session.csrfToken,
        tenantId,
        operatorTeamId,
        epochId,
        entry.id,
        entry.etag,
        { reason },
      );
      invalidateRosterInitialRequest();
      invalidateRosterPagination();
      onAuthorityChanged(request);
      if (!mutationIsCurrent(request)) return;
      setRevokeEntryId(null);
      setRevokeReason("");
      setRevokeReasonError(null);
      setRosterRevision((value) => value + 1);
    } catch (caught) {
      if (!mutationIsCurrent(request)) return;
      if (caught instanceof PhaseTwoApiError && caught.status === 401) {
        clearSession(session.id);
        return;
      }
      if (!revokeAllowedRef.current) return;
      setRevokeError(
        describePhaseTwoError(caught, "The roster edge was not revoked."),
      );
    } finally {
      finishMutation(request);
    }
  }

  async function loadMoreRoster(): Promise<void> {
    if (
      roster.kind !== "ready" ||
      !roster.nextCursor ||
      isLoadingMore ||
      rosterPaginationRequestRef.current
    )
      return;
    const cursor = roster.nextCursor;
    const controller = new AbortController();
    const request: RosterPaginationRequest = {
      boundaryKey: mutationBoundaryKey,
      controller,
      cursor,
      generation: rosterPaginationGenerationRef.current,
    };
    rosterPaginationRequestRef.current = request;
    setIsLoadingMore(true);
    setPaginationError(null);
    try {
      const page = await api.listOperatorTeamRosterEntries(
        tenantId,
        operatorTeamId,
        epochId,
        { after: cursor, includeRevoked: true, signal: controller.signal },
      );
      if (!rosterPaginationIsCurrent(request)) return;
      if (page.nextCursor === cursor)
        throw new Error("The roster cursor did not advance.");
      if (page.nextCursor && rosterCursorsRef.current.has(page.nextCursor)) {
        throw new Error("The roster cursor entered a cycle.");
      }
      if (page.nextCursor) rosterCursorsRef.current.add(page.nextCursor);
      setRoster((current) =>
        current.kind === "ready" && current.nextCursor === cursor
          ? {
              items: mergeRosterEntries(current.items, page.items),
              kind: "ready",
              ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
            }
          : current,
      );
    } catch (caught) {
      if (!rosterPaginationIsCurrent(request) || isAbortError(caught)) return;
      if (caught instanceof PhaseTwoApiError && caught.status === 401) {
        clearSession(session.id);
        return;
      }
      setPaginationError(
        describePhaseTwoError(
          caught,
          "The next roster page could not be loaded.",
        ),
      );
    } finally {
      if (rosterPaginationRequestRef.current === request) {
        rosterPaginationRequestRef.current = null;
        if (
          mountedRef.current &&
          mutationBoundaryRef.current === request.boundaryKey &&
          rosterPaginationGenerationRef.current === request.generation
        ) {
          setIsLoadingMore(false);
        }
      }
    }
  }

  function rosterPaginationIsCurrent(
    request: RosterPaginationRequest,
  ): boolean {
    return (
      mountedRef.current &&
      !request.controller.signal.aborted &&
      rosterPaginationRequestRef.current === request &&
      mutationBoundaryRef.current === request.boundaryKey &&
      rosterPaginationGenerationRef.current === request.generation
    );
  }

  function rosterInitialRequestIsCurrent(
    request: RosterInitialRequest,
    expectedPair: string,
  ): boolean {
    return (
      mountedRef.current &&
      !request.controller.signal.aborted &&
      rosterInitialRequestRef.current === request &&
      pairRef.current === expectedPair &&
      rosterBoundaryRef.current === request.boundaryKey &&
      rosterInitialGenerationRef.current === request.generation
    );
  }

  function reloadRoster(): void {
    invalidateRosterInitialRequest();
    invalidateRosterPagination();
    setRosterRevision((value) => value + 1);
  }

  async function loadMoreUsers(): Promise<void> {
    if (
      !canAddRoster ||
      !rosterMutationsOpen ||
      users.kind !== "ready" ||
      !users.nextCursor ||
      isLoadingMoreUsers
    ) {
      return;
    }
    const cursor = users.nextCursor;
    const expectedPair = pairKey;
    const controller = new AbortController();
    userRequestRef.current?.abort();
    userRequestRef.current = controller;
    setIsLoadingMoreUsers(true);
    setUserPaginationError(null);
    try {
      const page = await api.listTenantUsers(
        tenantId,
        cursor,
        controller.signal,
      );
      if (controller.signal.aborted || pairRef.current !== expectedPair) return;
      assertTenantUsers(page.items, tenantId);
      if (
        page.nextCursor === cursor ||
        (page.nextCursor && userCursorsRef.current.has(page.nextCursor))
      ) {
        setUsers((current) =>
          current.kind === "ready" && current.nextCursor === cursor
            ? { items: current.items, kind: "ready" }
            : current,
        );
        setUserPaginationError(
          page.nextCursor === cursor
            ? "The tenant-member cursor did not advance. Further pages were closed."
            : "The tenant-member cursor entered a cycle. Further pages were closed.",
        );
        return;
      }
      if (page.nextCursor) userCursorsRef.current.add(page.nextCursor);
      setUsers((current) =>
        current.kind === "ready" && current.nextCursor === cursor
          ? {
              items: mergeTenantUsers(current.items, page.items),
              kind: "ready",
              ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
            }
          : current,
      );
    } catch (caught) {
      if (
        controller.signal.aborted ||
        pairRef.current !== expectedPair ||
        isAbortError(caught)
      ) {
        return;
      }
      if (caught instanceof PhaseTwoApiError && caught.status === 401) {
        clearSession(session.id);
        return;
      }
      setUserPaginationError(
        describePhaseTwoError(
          caught,
          "The next tenant-member page could not be loaded.",
        ),
      );
    } finally {
      if (userRequestRef.current === controller) {
        userRequestRef.current = null;
      }
      if (pairRef.current === expectedPair) setIsLoadingMoreUsers(false);
    }
  }

  if (epoch.kind === "loading") return <EpochDetailSkeleton />;
  if (epoch.kind === "error") {
    return (
      <div className="operator-team-detail-error">
        <FocusedError message={epoch.message} />
        <Button
          type="button"
          variant="outline"
          disabled={mutationPending}
          onClick={() => setRevision((value) => value + 1)}
        >
          <RefreshCw aria-hidden="true" /> Retry exact epoch
        </Button>
      </div>
    );
  }

  const exactEpoch = epoch.resource.value;
  const historical = exactEpoch.state === "ended" || endCommitted;
  const activeUsers =
    users.kind === "ready"
      ? users.items.filter(
          (user) => user.membershipStatus === "active" && user.user.active,
        )
      : [];
  const revokeEntry =
    canRevokeRoster && !historical && roster.kind === "ready" && revokeEntryId
      ? roster.items.find(
          (entry) =>
            entry.id === revokeEntryId &&
            entry.state === "active" &&
            entry.managedByOperatorTeamApi,
        )
      : undefined;

  return (
    <div className="epoch-detail-ready">
      <header className="epoch-detail-header">
        <div>
          <p className="section-label">
            Exact epoch {shortId(exactEpoch.epochId)}
          </p>
          <h2>Roster · {exactEpoch.operatorTeam.name}</h2>
          <p>
            {historical
              ? "Historical roster: retained for audit and never part of the current assignment."
              : "Active roster: live edges can contribute only through this exact epoch."}
          </p>
        </div>
        <Badge variant={historical ? "outline" : "secondary"}>
          {historical ? "History only" : "Active authority"}
        </Badge>
      </header>

      <dl className="epoch-facts">
        <div>
          <dt>Team key</dt>
          <dd>{exactEpoch.operatorTeam.key}</dd>
        </div>
        <div>
          <dt>Epoch ID</dt>
          <dd>
            <code>{exactEpoch.epochId}</code>
          </dd>
        </div>
        <div>
          <dt>ETag</dt>
          <dd>
            <code>{epoch.resource.etag}</code>
          </dd>
        </div>
        <div>
          <dt>Started</dt>
          <dd>{formatDateTime(exactEpoch.startedAt)}</dd>
        </div>
      </dl>

      {endCommitted && exactEpoch.state === "active" ? (
        <Alert>
          <CheckCircle2 aria-hidden="true" />
          <AlertTitle>Epoch end committed</AlertTitle>
          <AlertDescription>
            <p>
              {endError ??
                "The mutation completed, but the ended representation still needs to be reloaded. Roster mutations stay closed meanwhile."}
            </p>
            <Button
              type="button"
              variant="outline"
              disabled={mutationPending}
              onClick={() => setRevision((value) => value + 1)}
            >
              <RefreshCw aria-hidden="true" /> Reload ended epoch
            </Button>
          </AlertDescription>
        </Alert>
      ) : null}

      {canEnd && !historical ? (
        <Card className="epoch-end-card">
          <CardHeader>
            <CardTitle>End this epoch</CardTitle>
            <CardDescription>
              Authority ends immediately; roster rows remain immutable history.
            </CardDescription>
          </CardHeader>
          <CardContent>
            {endError ? (
              <div className="operator-team-stale-block">
                <FocusedError message={endError} title="Epoch end failed" />
                <Button
                  type="button"
                  variant="outline"
                  disabled={mutationPending}
                  onClick={() => setRevision((value) => value + 1)}
                >
                  <RefreshCw aria-hidden="true" /> Load current epoch
                </Button>
              </div>
            ) : null}
            <FormField
              htmlFor={`${id}-end-reason`}
              label="End reason"
              {...(endReasonError ? { error: endReasonError } : {})}
            >
              <Textarea
                id={`${id}-end-reason`}
                value={endReason}
                required
                minLength={1}
                maxLength={500}
                disabled={mutationPending}
                aria-invalid={endReasonError ? true : undefined}
                aria-describedby={
                  endReasonError ? `${id}-end-reason-error` : undefined
                }
                onChange={(event) => {
                  const value = event.target.value;
                  setEndReason(value);
                  if (endReasonError) {
                    setEndReasonError(administrativeReasonError(value));
                  }
                }}
              />
            </FormField>
            <Button
              type="button"
              variant="destructive"
              disabled={
                mutationPending ||
                endReason.trim().length === 0 ||
                Boolean(endReasonError)
              }
              onClick={() => void endEpoch()}
            >
              <CircleStop aria-hidden="true" />{" "}
              {isEnding ? "Ending epoch…" : "End assignment epoch"}
            </Button>
          </CardContent>
        </Card>
      ) : null}

      {canAddRoster && !historical ? (
        <Card className="roster-add-card">
          <CardHeader>
            <CardTitle>Add exact-epoch roster edge</CardTitle>
            <CardDescription>
              Only active memberships are accepted. Optional expiry is an RFC
              3339 instant.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form className="roster-add-form" onSubmit={addRosterEntry}>
              {addError ? <FocusedError message={addError} /> : null}
              <FormField htmlFor={`${id}-member`} label="Tenant member">
                <Select
                  value={memberId}
                  onValueChange={setMemberId}
                  disabled={
                    mutationPending ||
                    users.kind !== "ready" ||
                    activeUsers.length === 0
                  }
                >
                  <SelectTrigger id={`${id}-member`} aria-label="Tenant member">
                    <SelectValue
                      placeholder={
                        users.kind === "loading"
                          ? "Loading tenant members…"
                          : users.kind === "error"
                            ? "Tenant members unavailable"
                            : activeUsers.length === 0
                              ? "No eligible users loaded"
                              : "Select tenant member"
                      }
                    />
                  </SelectTrigger>
                  <SelectContent>
                    {activeUsers.map((user) => (
                      <SelectItem
                        key={user.membershipId}
                        value={user.membershipId}
                      >
                        {user.user.displayName} · {user.user.email}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </FormField>
              <div className="roster-user-inventory">
                {users.kind === "error" ? (
                  <>
                    <FocusedError message={users.message} />
                    <Button
                      type="button"
                      variant="outline"
                      disabled={mutationPending}
                      onClick={() => setUserRevision((value) => value + 1)}
                    >
                      <RefreshCw aria-hidden="true" /> Retry tenant members
                    </Button>
                  </>
                ) : null}
                {userPaginationError ? (
                  <FocusedError
                    message={userPaginationError}
                    title="More tenant members could not be loaded"
                  />
                ) : null}
                {users.kind === "ready" ? (
                  <small>
                    {activeUsers.length} eligible tenant{" "}
                    {activeUsers.length === 1 ? "member" : "members"} loaded
                  </small>
                ) : null}
                {users.kind === "ready" && users.nextCursor ? (
                  <Button
                    type="button"
                    variant="outline"
                    disabled={mutationPending || isLoadingMoreUsers}
                    onClick={() => void loadMoreUsers()}
                  >
                    <ArrowDown aria-hidden="true" />{" "}
                    {isLoadingMoreUsers ? "Loading users…" : "Load more users"}
                  </Button>
                ) : null}
              </div>
              <FormField
                htmlFor={`${id}-add-reason`}
                label="Roster reason"
                {...(addReasonError ? { error: addReasonError } : {})}
              >
                <Input
                  id={`${id}-add-reason`}
                  value={addReason}
                  required
                  minLength={1}
                  maxLength={500}
                  disabled={mutationPending}
                  aria-invalid={addReasonError ? true : undefined}
                  aria-describedby={
                    addReasonError ? `${id}-add-reason-error` : undefined
                  }
                  onChange={(event) => {
                    const value = event.target.value;
                    setAddReason(value);
                    if (addReasonError) {
                      setAddReasonError(administrativeReasonError(value));
                    }
                  }}
                />
              </FormField>
              <FormField
                htmlFor={`${id}-expires-at`}
                label="Expires at"
                hint="Optional RFC 3339, for example 2026-09-01T08:00:00Z."
                optional
                {...(expiresAtError ? { error: expiresAtError } : {})}
              >
                <Input
                  id={`${id}-expires-at`}
                  value={expiresAt}
                  maxLength={35}
                  disabled={mutationPending}
                  placeholder="2026-09-01T08:00:00Z"
                  aria-invalid={expiresAtError ? true : undefined}
                  aria-describedby={`${id}-expires-at-${expiresAtError ? "error" : "hint"}`}
                  onChange={(event) => {
                    const value = event.target.value;
                    setExpiresAt(value);
                    if (expiresAtError) setExpiresAtError(null);
                  }}
                />
              </FormField>
              <Button
                type="submit"
                disabled={
                  mutationPending ||
                  !memberId ||
                  addReason.trim().length === 0 ||
                  Boolean(addReasonError) ||
                  Boolean(expiresAtError)
                }
              >
                <UserPlus aria-hidden="true" />{" "}
                {isAdding ? "Adding member…" : "Add roster member"}
              </Button>
            </form>
          </CardContent>
        </Card>
      ) : null}

      <section
        className="roster-section"
        aria-labelledby={`${id}-roster-title`}
      >
        <div className="operator-team-section-heading">
          <div>
            <p className="section-label">Epoch-bound edges</p>
            <h3 id={`${id}-roster-title`}>
              {historical ? "Historical roster" : "Active epoch roster"}
            </h3>
          </div>
          <Badge variant="outline">Epoch {shortId(epochId)}</Badge>
        </div>
        {roster.kind === "loading" ? <RosterSkeleton /> : null}
        {roster.kind === "error" ? (
          <div className="operator-team-detail-error">
            <FocusedError message={roster.message} />
            {canReadRoster ? (
              <Button
                type="button"
                variant="outline"
                disabled={mutationPending}
                onClick={reloadRoster}
              >
                <RefreshCw aria-hidden="true" /> Retry exact-epoch roster
              </Button>
            ) : null}
          </div>
        ) : null}
        {revokeError && canRevokeRoster && !historical ? (
          <div className="operator-team-stale-block">
            <FocusedError message={revokeError} title="Roster revoke failed" />
            <Button
              type="button"
              variant="outline"
              disabled={mutationPending}
              onClick={reloadRoster}
            >
              <RefreshCw aria-hidden="true" /> Reload exact-epoch roster
            </Button>
          </div>
        ) : null}
        {paginationError ? (
          <FocusedError
            message={paginationError}
            title="More roster entries could not be loaded"
          />
        ) : null}
        {roster.kind === "ready" && roster.items.length === 0 ? (
          <div className="operator-team-empty operator-team-empty--inline">
            <UsersRound aria-hidden="true" />
            <h3>No roster edges in this epoch</h3>
            <p>
              {historical
                ? "This historical epoch ended without roster entries."
                : "Add an active tenant member when its role consequences are understood."}
            </p>
          </div>
        ) : null}
        {roster.kind === "ready" && roster.items.length > 0 ? (
          <ul className="roster-list">
            {roster.items.map((entry) => (
              <li key={entry.id} data-state={entry.state}>
                <div className="roster-member">
                  <span className="roster-member__initials" aria-hidden="true">
                    {initials(entry.member.displayName)}
                  </span>
                  <span>
                    <strong>{entry.member.displayName}</strong>
                    <small>
                      {entry.member.membershipStatus} membership · edge{" "}
                      {shortId(entry.id)}
                    </small>
                  </span>
                </div>
                <div className="roster-provenance">
                  <Badge
                    variant={entry.state === "active" ? "secondary" : "outline"}
                  >
                    {entry.state}
                  </Badge>
                  <span>
                    {entry.provenance.sourceKind.replaceAll("_", " ")}
                  </span>
                  <time dateTime={entry.provenance.grantedAt}>
                    {formatDateTime(entry.provenance.grantedAt)}
                  </time>
                </div>
                {canRevokeRoster &&
                !historical &&
                entry.state === "active" &&
                entry.managedByOperatorTeamApi ? (
                  <Button
                    type="button"
                    size="sm"
                    variant="ghost"
                    disabled={mutationPending}
                    aria-label={`Revoke ${entry.member.displayName}, edge ${shortId(entry.id)}`}
                    onClick={() => {
                      setRevokeEntryId(entry.id);
                      setRevokeError(null);
                      setRevokeReasonError(null);
                    }}
                  >
                    <UserMinus aria-hidden="true" /> Revoke
                  </Button>
                ) : null}
              </li>
            ))}
          </ul>
        ) : null}
        {roster.kind === "ready" && roster.nextCursor ? (
          <Button
            type="button"
            variant="outline"
            disabled={mutationPending || isLoadingMore}
            onClick={() => void loadMoreRoster()}
          >
            <ArrowDown aria-hidden="true" />{" "}
            {isLoadingMore ? "Loading roster…" : "Load more roster entries"}
          </Button>
        ) : null}
      </section>

      {revokeEntry ? (
        <Card className="roster-revoke-card">
          <CardHeader>
            <CardTitle>Revoke {revokeEntry.member.displayName}</CardTitle>
            <CardDescription>
              This changes only edge {shortId(revokeEntry.id)} in epoch{" "}
              {shortId(epochId)}.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <FormField
              htmlFor={`${id}-revoke-reason`}
              label="Revoke reason"
              {...(revokeReasonError ? { error: revokeReasonError } : {})}
            >
              <Textarea
                id={`${id}-revoke-reason`}
                value={revokeReason}
                required
                minLength={1}
                maxLength={500}
                disabled={mutationPending}
                aria-invalid={revokeReasonError ? true : undefined}
                aria-describedby={
                  revokeReasonError ? `${id}-revoke-reason-error` : undefined
                }
                onChange={(event) => {
                  const value = event.target.value;
                  setRevokeReason(value);
                  if (revokeReasonError) {
                    setRevokeReasonError(administrativeReasonError(value));
                  }
                }}
              />
            </FormField>
            <div className="operator-team-heading-actions">
              <Button
                type="button"
                variant="outline"
                disabled={mutationPending}
                onClick={() => {
                  setRevokeEntryId(null);
                  setRevokeReason("");
                  setRevokeReasonError(null);
                }}
              >
                Cancel
              </Button>
              <Button
                type="button"
                variant="destructive"
                disabled={
                  mutationPending ||
                  revokeReason.trim().length === 0 ||
                  Boolean(revokeReasonError)
                }
                onClick={() => void revokeRosterEntry()}
              >
                <UserMinus aria-hidden="true" />{" "}
                {isRevoking ? "Revoking edge…" : "Revoke roster edge"}
              </Button>
            </div>
          </CardContent>
        </Card>
      ) : null}
    </div>
  );
}

function TenantOperatorTeamSkeleton(): React.JSX.Element {
  return (
    <div
      className="content operator-team-page"
      aria-label="Loading tenant operator-team authority"
    >
      <div className="operator-team-detail-skeleton">
        <span />
        <span />
        <span />
      </div>
    </div>
  );
}

function EpochRailSkeleton(): React.JSX.Element {
  return (
    <div className="epoch-rail-skeleton" aria-label="Loading assignment epochs">
      <span />
      <span />
      <span />
    </div>
  );
}

function EpochDetailSkeleton(): React.JSX.Element {
  return (
    <div
      className="operator-team-detail-skeleton"
      aria-label="Loading exact assignment epoch"
    >
      <span />
      <span />
      <span />
    </div>
  );
}

function RosterSkeleton(): React.JSX.Element {
  return (
    <div className="roster-skeleton" aria-label="Loading exact-epoch roster">
      <span />
      <span />
      <span />
    </div>
  );
}

export function mergeAssignmentEpochs(
  current: readonly OperatorTeamAssignmentEpochView[],
  incoming: readonly OperatorTeamAssignmentEpochView[],
  tenantId: string,
): readonly OperatorTeamAssignmentEpochView[] {
  const byId = new Map(current.map((epoch) => [epoch.epochId, epoch]));
  for (const epoch of incoming) {
    if (epoch.tenantId !== tenantId) {
      throw new Error(
        "An assignment epoch crossed the active tenant boundary.",
      );
    }
    const existing = byId.get(epoch.epochId);
    if (!existing || epoch.version > existing.version) {
      byId.set(epoch.epochId, epoch);
    } else if (
      epoch.version === existing.version &&
      JSON.stringify(epoch) !== JSON.stringify(existing)
    ) {
      throw new Error(
        "Assignment-epoch pages returned conflicting representations.",
      );
    }
  }
  return [...byId.values()].toSorted((left, right) => {
    if (left.state !== right.state) return left.state === "active" ? -1 : 1;
    return right.startedAt.localeCompare(left.startedAt);
  });
}

export function mergeRosterEntries(
  current: readonly OperatorTeamRosterEntryView[],
  incoming: readonly OperatorTeamRosterEntryView[],
): readonly OperatorTeamRosterEntryView[] {
  const byId = new Map(current.map((entry) => [entry.id, entry]));
  for (const entry of incoming) {
    const existing = byId.get(entry.id);
    if (!existing || entry.version > existing.version)
      byId.set(entry.id, entry);
    else if (
      entry.version === existing.version &&
      JSON.stringify(entry) !== JSON.stringify(existing)
    ) {
      throw new Error(
        "Roster pages returned conflicting edge representations.",
      );
    }
  }
  return [...byId.values()].toSorted((left, right) =>
    left.member.displayName.localeCompare(right.member.displayName),
  );
}

function mergeTenantUsers(
  current: readonly TenantUserSummaryView[],
  incoming: readonly TenantUserSummaryView[],
): readonly TenantUserSummaryView[] {
  const byMembershipId = new Map(
    current.map((user) => [user.membershipId, user]),
  );
  for (const user of incoming) byMembershipId.set(user.membershipId, user);
  return [...byMembershipId.values()];
}

function assertTenantUsers(
  users: readonly TenantUserSummaryView[],
  tenantId: string,
): void {
  if (users.some((user) => user.tenantId !== tenantId)) {
    throw new Error("The tenant-member response escaped the active tenant.");
  }
}

function shortId(value: string): string {
  return value.slice(-8);
}

function initials(value: string): string {
  return value
    .split(/\s+/u)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase() ?? "")
    .join("");
}

function formatDateTime(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function isAbortError(error: unknown): boolean {
  return error instanceof DOMException && error.name === "AbortError";
}

function administrativeReasonError(value: string): string | null {
  const reason = value.trim();
  if (!reason) return "Enter an administrative reason.";
  if (reason.length > 500) return "Use 500 characters or fewer.";
  return hasControlCharacters(reason)
    ? "Use a reason without control characters."
    : null;
}

function rosterExpiryError(
  value: string,
  allowPastBoundReplay = false,
): string | null {
  const expiresAt = value.trim();
  if (!expiresAt) return null;
  const instant = parseRfc3339Instant(expiresAt);
  if (
    instant === undefined ||
    maximumRosterExpiryInstant === undefined ||
    instant % 1_000n !== 0n ||
    instant > maximumRosterExpiryInstant
  ) {
    return "Use an RFC 3339 expiry with microsecond-safe precision.";
  }
  return instant <= currentInstant() && !allowPastBoundReplay
    ? "Choose an expiry in the future."
    : null;
}

function epochMutationIdentityKey(
  tenantId: string,
  operatorTeamId: string,
  epochId: string,
): string {
  return JSON.stringify([tenantId, operatorTeamId, epochId]);
}

function operatorTeamStartIdentityKey(tenantId: string): string {
  return JSON.stringify([tenantId]);
}
