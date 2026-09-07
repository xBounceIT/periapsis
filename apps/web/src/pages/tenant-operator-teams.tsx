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
import {
  useCallback,
  useEffect,
  useId,
  useLayoutEffect,
  useMemo,
  useReducer,
  useRef,
} from "react";
import { TenantRequiredPage } from "../components/tenant-required-page";
import {
  mergeAssignmentEpochs,
  mergeRosterEntries,
} from "./tenant-operator-teams-model";
import { reduceWorkspaceState } from "./workspace-state";

import { useSession } from "../auth/session-context";
import { useTenantAuthority } from "../auth/tenant-authority-context";
import { FocusedError } from "../components/focused-error";
import { FormField } from "../components/form-field";
import { ServerDenied } from "../components/server-denied";
import { readTextField } from "../lib/form-data";
import {
  describePhaseTwoError,
  PhaseTwoApiError,
  type OperatorTeamAssignmentEpochView,
  type OperatorTeamRosterEntryCreateInput,
  type OperatorTeamRosterEntryView,
  type TenantUserSummaryView,
  type VersionedView,
} from "../lib/phase-two-types";
import { currentInstant, parseRfc3339Instant } from "../lib/rfc3339-instant";
import { hasControlCharacters } from "../lib/text-validation";

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
  const model = useTenantOperatorTeamsPageModel();
  if (model.kind === "content") return model.content;
  return <TenantOperatorTeamsPageView model={model.data} />;
}

function useTenantOperatorTeamsPageModel() {
  const { api, clearSession, session } = useSession();
  const authority = useTenantAuthority();
  const tenantId = session.activeTenantId;
  const pairKey = authority.pairKey;
  const pairRef = useRef(pairKey);
  useLayoutEffect(() => {
    pairRef.current = pairKey;
  });
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
  useLayoutEffect(() => {
    startAllowedRef.current =
      Boolean(tenantId) && authority.status === "ready" && canRead && canManage;
  });
  useLayoutEffect(() => {
    authorityRevisionRef.current = authority.revision;
  });
  const [workspaceState, updateWorkspaceState] = useReducer(
    reduceWorkspaceState<TenantOperatorTeamsPageState>,
    undefined,
    (): TenantOperatorTeamsPageState => ({
      listState: {
        kind: "loading",
      },
      listRevision: 0,
      selection: null,
      isLoadingMore: false,
      paginationError: null,
      isStarting: false,
      startError: null,
      startReasonError: null,
      notice: null,
    }),
  );
  const {
    listState,
    listRevision,
    selection,
    isLoadingMore,
    paginationError,
    isStarting,
    startError,
    startReasonError,
    notice,
  } = workspaceState;
  const {
    setListState,
    setListRevision,
    setSelection,
    setIsLoadingMore,
    setPaginationError,
    setIsStarting,
    setStartError,
    setStartReasonError,
    setNotice,
  } = useMemo(
    () => ({
      setListState: (
        value: React.SetStateAction<TenantOperatorTeamsPageState["listState"]>,
      ) => updateWorkspaceState({ listState: value }),
      setListRevision: (
        value: React.SetStateAction<
          TenantOperatorTeamsPageState["listRevision"]
        >,
      ) => updateWorkspaceState({ listRevision: value }),
      setSelection: (
        value: React.SetStateAction<TenantOperatorTeamsPageState["selection"]>,
      ) => updateWorkspaceState({ selection: value }),
      setIsLoadingMore: (
        value: React.SetStateAction<
          TenantOperatorTeamsPageState["isLoadingMore"]
        >,
      ) => updateWorkspaceState({ isLoadingMore: value }),
      setPaginationError: (
        value: React.SetStateAction<
          TenantOperatorTeamsPageState["paginationError"]
        >,
      ) => updateWorkspaceState({ paginationError: value }),
      setIsStarting: (
        value: React.SetStateAction<TenantOperatorTeamsPageState["isStarting"]>,
      ) => updateWorkspaceState({ isStarting: value }),
      setStartError: (
        value: React.SetStateAction<TenantOperatorTeamsPageState["startError"]>,
      ) => updateWorkspaceState({ startError: value }),
      setStartReasonError: (
        value: React.SetStateAction<
          TenantOperatorTeamsPageState["startReasonError"]
        >,
      ) => updateWorkspaceState({ startReasonError: value }),
      setNotice: (
        value: React.SetStateAction<TenantOperatorTeamsPageState["notice"]>,
      ) => updateWorkspaceState({ notice: value }),
    }),
    [updateWorkspaceState],
  );

  const activeMutationRef = useRef<OperatorTeamMutationRequest | null>(null);
  const coordinatorPairRef = useRef(pairKey);
  const observedExplicitRevisionRef = useRef(authority.explicitRevision);
  const startGenerationRef = useRef(0);
  const startRequestRef = useRef<OperatorTeamMutationRequest | null>(null);
  const paginationCursorsRef = useRef<Set<string>>(new Set());
  const paginationRequestRef = useRef<AbortController | null>(null);
  const id = useId();

  useLayoutEffect(() => {
    if (coordinatorPairRef.current !== pairKey) {
      coordinatorPairRef.current = pairKey;
      startRequestRef.current = null;
      startGenerationRef.current += 1;
      observedExplicitRevisionRef.current = authority.explicitRevision;
    }
  });

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
    updateWorkspaceState({
      selection: null,
      paginationError: null,
      isLoadingMore: false,
      isStarting: false,
      startError: null,
      startReasonError: null,
      notice: null,
    });
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
      updateWorkspaceState({
        isStarting: false,
        startError: null,
        startReasonError: null,
        notice: null,
      });
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
    updateWorkspaceState({
      isStarting: false,
      startError: null,
      startReasonError: null,
      notice: null,
    });
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
    setPaginationError,
    setIsLoadingMore,
    setListState,
    setSelection,
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
    updateWorkspaceState({ isLoadingMore: true, paginationError: null });
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
      // react-doctor-disable-next-line no-loading-flag-reset-outside-finally -- The owning request clears this flag in finally; the generation guard protects newer requests.
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
    updateWorkspaceState({ startError: null, notice: null, isStarting: true });
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
      updateWorkspaceState({
        listState: (current) =>
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
        selection: {
          epochId: created.value.epochId,
          operatorTeamId: created.value.operatorTeam.id,
          pairKey: requestedPair,
        },
        notice: {
          kind: "start",
          state: created.value.state,
          teamName: created.value.operatorTeam.name,
        },
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
    return {
      kind: "content" as const,
      content: (
        <TenantRequiredPage
          label="Tenant operations"
          title="Select a tenant to inspect operator teams."
        >
          The tenant switcher establishes the explicit authorization and RLS
          context.
        </TenantRequiredPage>
      ),
    };
  }
  if (authority.status === "forbidden" || listState.kind === "forbidden") {
    return {
      kind: "content" as const,
      content: <ServerDenied resource="operator-team assignment epochs" />,
    };
  }
  if (authority.status === "error") {
    return {
      kind: "content" as const,
      content: (
        <div className="content content--narrow">
          <FocusedError
            message={
              authority.message ?? "Tenant authority could not be loaded."
            }
          />
          <Button type="button" variant="outline" onClick={authority.reload}>
            <RefreshCw aria-hidden="true" /> Reload tenant authority
          </Button>
        </div>
      ),
    };
  }
  if (authority.status !== "ready") {
    return {
      kind: "content" as const,
      content: <TenantOperatorTeamSkeleton />,
    };
  }
  if (!canRead) {
    return {
      kind: "content" as const,
      content: <ServerDenied resource="tenant operator-team inventory" />,
    };
  }

  const selected = selection?.pairKey === pairKey ? selection : null;
  const mutationPending = authority.hasPendingMutation(pairKey);

  return {
    kind: "ready" as const,
    data: {
      canAddRoster,
      canEnd,
      canManage,
      canReadRoster,
      canRevokeRoster,
      detachMutation,
      id,
      isLoadingMore,
      isStarting,
      listState,
      loadMore,
      mutationPending,
      notice,
      paginationError,
      pairKey,
      registerMutation,
      requestAuthorityReload,
      selected,
      setListRevision,
      setListState,
      setNotice,
      setSelection,
      setStartReasonError,
      settleMutation,
      startEpoch,
      startError,
      startReasonError,
      tenantId,
    },
  };
}

function TenantOperatorTeamsPageView({
  model,
}: {
  model: Extract<
    ReturnType<typeof useTenantOperatorTeamsPageModel>,
    { kind: "ready" }
  >["data"];
}): React.JSX.Element {
  const { listState, paginationError, setListRevision } = model;
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

      {<EpochMutationNotice model={model} />}

      {<StartEpochAction model={model} />}

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
      {<EpochInventoryBoundary model={model} />}
    </div>
  );
}

function EpochDetail(props: {
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
  const model = useEpochDetailModel(props);
  if (model.kind === "content") return model.content;
  return <EpochDetailView model={model.data} />;
}

function useEpochDetailModel({
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
}) {
  const { api, clearSession, session } = useSession();
  const authority = useTenantAuthority();
  const [workspaceState, updateWorkspaceState] = useReducer(
    reduceWorkspaceState<EpochDetailState>,
    undefined,
    (): EpochDetailState => ({
      epoch: { kind: "loading" },
      roster: { kind: "loading" },
      users: { kind: "loading" },
      userRevision: 0,
      isLoadingMoreUsers: false,
      userPaginationError: null,
      revision: 0,
      rosterRevision: 0,
      isLoadingMore: false,
      paginationError: null,
      endReason: "",
      endReasonError: null,
      endError: null,
      isEnding: false,
      endCommitted: false,
      memberId: "",
      addReason: "",
      addReasonError: null,
      expiresAt: "",
      expiresAtError: null,
      addError: null,
      isAdding: false,
      revokeEntryId: null,
      revokeReason: "",
      revokeReasonError: null,
      revokeError: null,
      isRevoking: false,
    }),
  );
  const {
    epoch,
    roster,
    users,
    userRevision,
    isLoadingMoreUsers,
    userPaginationError,
    revision,
    rosterRevision,
    isLoadingMore,
    paginationError,
    endReason,
    endReasonError,
    endError,
    isEnding,
    endCommitted,
    memberId,
    addReason,
    addReasonError,
    expiresAt,
    expiresAtError,
    addError,
    isAdding,
    revokeEntryId,
    revokeReason,
    revokeReasonError,
    revokeError,
    isRevoking,
  } = workspaceState;
  const {
    setEpoch,
    setRoster,
    setUsers,
    setUserRevision,
    setIsLoadingMoreUsers,
    setUserPaginationError,
    setRevision,
    setRosterRevision,
    setIsLoadingMore,
    setPaginationError,
    setEndReason,
    setEndReasonError,
    setEndError,
    setIsEnding,
    setMemberId,
    setAddReason,
    setAddReasonError,
    setExpiresAt,
    setExpiresAtError,
    setAddError,
    setIsAdding,
    setRevokeEntryId,
    setRevokeReason,
    setRevokeReasonError,
    setRevokeError,
    setIsRevoking,
  } = useMemo(
    () => ({
      setEpoch: (value: React.SetStateAction<EpochDetailState["epoch"]>) =>
        updateWorkspaceState({ epoch: value }),
      setRoster: (value: React.SetStateAction<EpochDetailState["roster"]>) =>
        updateWorkspaceState({ roster: value }),
      setUsers: (value: React.SetStateAction<EpochDetailState["users"]>) =>
        updateWorkspaceState({ users: value }),
      setUserRevision: (
        value: React.SetStateAction<EpochDetailState["userRevision"]>,
      ) => updateWorkspaceState({ userRevision: value }),
      setIsLoadingMoreUsers: (
        value: React.SetStateAction<EpochDetailState["isLoadingMoreUsers"]>,
      ) => updateWorkspaceState({ isLoadingMoreUsers: value }),
      setUserPaginationError: (
        value: React.SetStateAction<EpochDetailState["userPaginationError"]>,
      ) => updateWorkspaceState({ userPaginationError: value }),
      setRevision: (
        value: React.SetStateAction<EpochDetailState["revision"]>,
      ) => updateWorkspaceState({ revision: value }),
      setRosterRevision: (
        value: React.SetStateAction<EpochDetailState["rosterRevision"]>,
      ) => updateWorkspaceState({ rosterRevision: value }),
      setIsLoadingMore: (
        value: React.SetStateAction<EpochDetailState["isLoadingMore"]>,
      ) => updateWorkspaceState({ isLoadingMore: value }),
      setPaginationError: (
        value: React.SetStateAction<EpochDetailState["paginationError"]>,
      ) => updateWorkspaceState({ paginationError: value }),
      setEndReason: (
        value: React.SetStateAction<EpochDetailState["endReason"]>,
      ) => updateWorkspaceState({ endReason: value }),
      setEndReasonError: (
        value: React.SetStateAction<EpochDetailState["endReasonError"]>,
      ) => updateWorkspaceState({ endReasonError: value }),
      setEndError: (
        value: React.SetStateAction<EpochDetailState["endError"]>,
      ) => updateWorkspaceState({ endError: value }),
      setIsEnding: (
        value: React.SetStateAction<EpochDetailState["isEnding"]>,
      ) => updateWorkspaceState({ isEnding: value }),
      setMemberId: (
        value: React.SetStateAction<EpochDetailState["memberId"]>,
      ) => updateWorkspaceState({ memberId: value }),
      setAddReason: (
        value: React.SetStateAction<EpochDetailState["addReason"]>,
      ) => updateWorkspaceState({ addReason: value }),
      setAddReasonError: (
        value: React.SetStateAction<EpochDetailState["addReasonError"]>,
      ) => updateWorkspaceState({ addReasonError: value }),
      setExpiresAt: (
        value: React.SetStateAction<EpochDetailState["expiresAt"]>,
      ) => updateWorkspaceState({ expiresAt: value }),
      setExpiresAtError: (
        value: React.SetStateAction<EpochDetailState["expiresAtError"]>,
      ) => updateWorkspaceState({ expiresAtError: value }),
      setAddError: (
        value: React.SetStateAction<EpochDetailState["addError"]>,
      ) => updateWorkspaceState({ addError: value }),
      setIsAdding: (
        value: React.SetStateAction<EpochDetailState["isAdding"]>,
      ) => updateWorkspaceState({ isAdding: value }),
      setRevokeEntryId: (
        value: React.SetStateAction<EpochDetailState["revokeEntryId"]>,
      ) => updateWorkspaceState({ revokeEntryId: value }),
      setRevokeReason: (
        value: React.SetStateAction<EpochDetailState["revokeReason"]>,
      ) => updateWorkspaceState({ revokeReason: value }),
      setRevokeReasonError: (
        value: React.SetStateAction<EpochDetailState["revokeReasonError"]>,
      ) => updateWorkspaceState({ revokeReasonError: value }),
      setRevokeError: (
        value: React.SetStateAction<EpochDetailState["revokeError"]>,
      ) => updateWorkspaceState({ revokeError: value }),
      setIsRevoking: (
        value: React.SetStateAction<EpochDetailState["isRevoking"]>,
      ) => updateWorkspaceState({ isRevoking: value }),
    }),
    [updateWorkspaceState],
  );

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
  useLayoutEffect(() => {
    pairRef.current = pairKey;
  });
  const rosterBoundaryKey = JSON.stringify([
    pairKey,
    tenantId,
    operatorTeamId,
    epochId,
  ]);
  const rosterBoundaryRef = useRef(rosterBoundaryKey);
  useLayoutEffect(() => {
    rosterBoundaryRef.current = rosterBoundaryKey;
  });
  const id = useId();

  const invalidateRosterPagination = useCallback((): void => {
    rosterPaginationGenerationRef.current += 1;
    const request = rosterPaginationRequestRef.current;
    rosterPaginationRequestRef.current = null;
    request?.controller.abort();
    if (mountedRef.current) setIsLoadingMore(false);
  }, [setIsLoadingMore]);

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
  useLayoutEffect(() => {
    if (mutationBoundaryRef.current !== mutationBoundaryKey) {
      mutationBoundaryRef.current = mutationBoundaryKey;
      mutationGenerationRef.current += 1;
    }
  });
  useLayoutEffect(() => {
    canAddRosterRef.current = canAddRoster && rosterMutationsOpen;
  });
  useLayoutEffect(() => {
    canEndRef.current = canEnd && rosterMutationsOpen;
  });
  useLayoutEffect(() => {
    revokeAllowedRef.current = canRevokeRoster && rosterMutationsOpen;
  });
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
    updateWorkspaceState({
      isAdding: false,
      isEnding: false,
      isRevoking: false,
      addError: null,
      addReasonError: null,
      endError: null,
      endReasonError: null,
      expiresAtError: null,
      revokeError: null,
      revokeReasonError: null,
    });
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
        updateWorkspaceState({
          epoch: { kind: "ready", resource },
          endError: null,
        });
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
    setEpoch,
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
        updateWorkspaceState({
          roster: {
            items: page.items,
            kind: "ready",
            ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
          },
          revokeError: null,
        });
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
    setPaginationError,
    setRoster,
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
    updateWorkspaceState({
      isLoadingMoreUsers: false,
      userPaginationError: null,
    });
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
    setUsers,
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
    updateWorkspaceState({
      memberId: "",
      addReason: "",
      expiresAt: "",
      addError: null,
      addReasonError: null,
      expiresAtError: null,
    });
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
    updateWorkspaceState({
      revokeEntryId: null,
      revokeReason: "",
      revokeError: null,
      revokeReasonError: null,
    });
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
    updateWorkspaceState({ endError: null, isEnding: true });
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
      updateWorkspaceState({
        endCommitted: true,
        rosterRevision: (value) => value + 1,
      });
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
      // react-doctor-disable-next-line no-loading-flag-reset-outside-finally -- The owning request clears this flag in finally; the generation guard protects newer requests.
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
    updateWorkspaceState({
      addReasonError: reasonError,
      expiresAtError: expiryError,
    });
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
    updateWorkspaceState({ addError: null, isAdding: true });
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
      updateWorkspaceState({
        memberId: "",
        addReason: "",
        expiresAt: "",
        addReasonError: null,
        expiresAtError: null,
      });
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
    updateWorkspaceState({ revokeError: null, isRevoking: true });
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
      updateWorkspaceState({
        revokeEntryId: null,
        revokeReason: "",
        revokeReasonError: null,
        rosterRevision: (value) => value + 1,
      });
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
    updateWorkspaceState({ isLoadingMore: true, paginationError: null });
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
          // react-doctor-disable-next-line no-loading-flag-reset-outside-finally -- The owning request clears this flag in finally; the generation guard protects newer requests.
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
    updateWorkspaceState({
      isLoadingMoreUsers: true,
      userPaginationError: null,
    });
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
        updateWorkspaceState({
          users: (current) =>
            current.kind === "ready" && current.nextCursor === cursor
              ? { items: current.items, kind: "ready" }
              : current,
          userPaginationError:
            page.nextCursor === cursor
              ? "The tenant-member cursor did not advance. Further pages were closed."
              : "The tenant-member cursor entered a cycle. Further pages were closed.",
        });
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
      // react-doctor-disable-next-line no-loading-flag-reset-outside-finally -- The owning request clears this flag in finally; the generation guard protects newer requests.
      if (pairRef.current === expectedPair) setIsLoadingMoreUsers(false);
    }
  }

  if (epoch.kind === "loading")
    return { kind: "content" as const, content: <EpochDetailSkeleton /> };
  if (epoch.kind === "error") {
    return {
      kind: "content" as const,
      content: (
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
      ),
    };
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

  return {
    kind: "ready" as const,
    data: {
      activeUsers,
      addError,
      addReason,
      addReasonError,
      addRosterEntry,
      canAddRoster,
      canEnd,
      canReadRoster,
      canRevokeRoster,
      endCommitted,
      endEpoch,
      endError,
      endReason,
      endReasonError,
      epoch,
      epochId,
      exactEpoch,
      expiresAt,
      expiresAtError,
      historical,
      id,
      isAdding,
      isEnding,
      isLoadingMore,
      isLoadingMoreUsers,
      isRevoking,
      loadMoreRoster,
      loadMoreUsers,
      memberId,
      mutationPending,
      paginationError,
      reloadRoster,
      revokeEntry,
      revokeError,
      revokeReason,
      revokeReasonError,
      revokeRosterEntry,
      roster,
      setAddReason,
      setAddReasonError,
      setEndReason,
      setEndReasonError,
      setExpiresAt,
      setExpiresAtError,
      setMemberId,
      setRevision,
      setRevokeEntryId,
      setRevokeError,
      setRevokeReason,
      setRevokeReasonError,
      setUserRevision,
      userPaginationError,
      users,
    },
  };
}

function EpochDetailView({
  model,
}: {
  model: Extract<
    ReturnType<typeof useEpochDetailModel>,
    { kind: "ready" }
  >["data"];
}): React.JSX.Element {
  const {
    endCommitted,
    endError,
    epoch,
    exactEpoch,
    historical,
    mutationPending,
    setRevision,
  } = model;
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

      {<EndEpochAction model={model} />}

      {<RosterAddAction model={model} />}

      <EpochRoster model={model} />

      {<RosterRevokeAction model={model} />}
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

function StartEpochAction({
  model,
}: {
  model: React.ComponentProps<typeof TenantOperatorTeamsPageView>["model"];
}): React.ReactNode {
  const { canManage } = model;
  return canManage ? <StartEpochForm model={model} /> : null;
}

function EpochInventoryBoundary({
  model,
}: {
  model: React.ComponentProps<typeof TenantOperatorTeamsPageView>["model"];
}): React.ReactNode {
  const { listState } = model;
  return listState.kind === "ready" && listState.items.length > 0 ? (
    <div className="epoch-workbench">
      <EpochInventory model={model} />

      <EpochInventoryItems model={model} />
    </div>
  ) : null;
}

function EndEpochAction({
  model,
}: {
  model: React.ComponentProps<typeof EpochDetailView>["model"];
}): React.ReactNode {
  const { canEnd, historical } = model;
  return canEnd && !historical ? <EndEpochForm model={model} /> : null;
}

function RosterAddAction({
  model,
}: {
  model: React.ComponentProps<typeof EpochDetailView>["model"];
}): React.ReactNode {
  const {
    addError,
    addReason,
    addReasonError,
    addRosterEntry,
    canAddRoster,
    expiresAt,
    expiresAtError,
    historical,
    id,
    isAdding,
    memberId,
    mutationPending,
    setAddReason,
    setAddReasonError,
    setExpiresAt,
    setExpiresAtError,
  } = model;
  return canAddRoster && !historical ? (
    <Card className="roster-add-card">
      <CardHeader>
        <CardTitle>Add exact-epoch roster edge</CardTitle>
        <CardDescription>
          Only active memberships are accepted. Optional expiry is an RFC 3339
          instant.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <RosterAddForm
          addError={addError}
          addReason={addReason}
          addReasonError={addReasonError}
          addRosterEntry={addRosterEntry}
          expiresAt={expiresAt}
          expiresAtError={expiresAtError}
          id={id}
          isAdding={isAdding}
          memberId={memberId}
          model={model}
          mutationPending={mutationPending}
          setAddReason={setAddReason}
          setAddReasonError={setAddReasonError}
          setExpiresAt={setExpiresAt}
          setExpiresAtError={setExpiresAtError}
        />
      </CardContent>
    </Card>
  ) : null;
}

function EpochRoster({
  model,
}: {
  model: React.ComponentProps<typeof EpochDetailView>["model"];
}): React.ReactNode {
  const {
    canRevokeRoster,
    epochId,
    historical,
    id,
    isLoadingMore,
    loadMoreRoster,
    mutationPending,
    paginationError,
    reloadRoster,
    revokeError,
    roster,
  } = model;
  return (
    <section className="roster-section" aria-labelledby={`${id}-roster-title`}>
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
      <RosterLoadError model={model} />
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
      {<RosterInventory model={model} />}
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
  );
}

function RosterRevokeAction({
  model,
}: {
  model: React.ComponentProps<typeof EpochDetailView>["model"];
}): React.ReactNode {
  const { revokeEntry } = model;
  return revokeEntry ? <RosterRevokeForm model={model} /> : null;
}

interface TenantOperatorTeamsPageState {
  listState: EpochListState;
  listRevision: number;
  selection: EpochSelection | null;
  isLoadingMore: boolean;
  paginationError: string | null;
  isStarting: boolean;
  startError: string | null;
  startReasonError: string | null;
  notice: TenantTeamNotice | null;
}

interface EpochDetailState {
  epoch:
    | { kind: "error"; message: string }
    | { kind: "loading" }
    | {
        kind: "ready";
        resource: VersionedView<OperatorTeamAssignmentEpochView>;
      };
  roster:
    | { kind: "error"; message: string }
    | { kind: "loading" }
    | {
        kind: "ready";
        items: readonly OperatorTeamRosterEntryView[];
        nextCursor?: string;
      };
  users: UserInventoryState;
  userRevision: number;
  isLoadingMoreUsers: boolean;
  userPaginationError: string | null;
  revision: number;
  rosterRevision: number;
  isLoadingMore: boolean;
  paginationError: string | null;
  endReason: string;
  endReasonError: string | null;
  endError: string | null;
  isEnding: boolean;
  endCommitted: boolean;
  memberId: string;
  addReason: string;
  addReasonError: string | null;
  expiresAt: string;
  expiresAtError: string | null;
  addError: string | null;
  isAdding: boolean;
  revokeEntryId: string | null;
  revokeReason: string;
  revokeReasonError: string | null;
  revokeError: string | null;
  isRevoking: boolean;
}

function EpochMutationNotice({
  model,
}: {
  model: React.ComponentProps<typeof TenantOperatorTeamsPageView>["model"];
}): React.ReactNode {
  const { notice } = model;
  return notice ? (
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
  ) : null;
}

function StartEpochForm({
  model,
}: {
  model: React.ComponentProps<typeof StartEpochAction>["model"];
}): React.ReactNode {
  const {
    id,
    isStarting,
    mutationPending,
    setStartReasonError,
    startEpoch,
    startError,
    startReasonError,
  } = model;
  return (
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
  );
}

function EpochInventory({
  model,
}: {
  model: React.ComponentProps<typeof EpochInventoryBoundary>["model"];
}): React.ReactNode {
  const {
    pairKey,
    isLoadingMore,
    listState,
    loadMore,
    selected,
    setSelection,
  } = model;
  if (listState.kind !== "ready") return null;
  return (
    <aside className="epoch-rail-panel" aria-labelledby="epoch-rail-title">
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
                    {epoch.operatorTeam.key} · epoch {shortId(epoch.epochId)}
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
  );
}

function EpochInventoryItems({
  model,
}: {
  model: React.ComponentProps<typeof EpochInventoryBoundary>["model"];
}): React.ReactNode {
  const {
    canAddRoster,
    canEnd,
    canReadRoster,
    canRevokeRoster,
    detachMutation,
    mutationPending,
    pairKey,
    registerMutation,
    requestAuthorityReload,
    selected,
    setListState,
    setNotice,
    settleMutation,
    tenantId,
  } = model;
  return (
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
  );
}

function EndEpochForm({
  model,
}: {
  model: React.ComponentProps<typeof EndEpochAction>["model"];
}): React.ReactNode {
  const {
    endEpoch,
    endError,
    endReason,
    endReasonError,
    id,
    isEnding,
    mutationPending,
    setEndReason,
    setEndReasonError,
    setRevision,
  } = model;
  return (
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
  );
}

function RosterMembershipField({
  model,
}: {
  model: React.ComponentProps<typeof RosterAddAction>["model"];
}): React.ReactNode {
  const { activeUsers, id, memberId, mutationPending, setMemberId, users } =
    model;
  return (
    <FormField htmlFor={`${id}-member`} label="Tenant member">
      <Select
        value={memberId}
        onValueChange={setMemberId}
        disabled={
          mutationPending || users.kind !== "ready" || activeUsers.length === 0
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
            <SelectItem key={user.membershipId} value={user.membershipId}>
              {user.user.displayName} · {user.user.email ?? "No email"}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </FormField>
  );
}

function RosterMembershipPagination({
  model,
}: {
  model: React.ComponentProps<typeof RosterAddAction>["model"];
}): React.ReactNode {
  const {
    activeUsers,
    isLoadingMoreUsers,
    loadMoreUsers,
    mutationPending,
    setUserRevision,
    userPaginationError,
    users,
  } = model;
  return (
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
  );
}

function RosterInventory({
  model,
}: {
  model: React.ComponentProps<typeof EpochRoster>["model"];
}): React.ReactNode {
  const {
    canRevokeRoster,
    historical,
    mutationPending,
    roster,
    setRevokeEntryId,
    setRevokeError,
    setRevokeReasonError,
  } = model;
  return roster.kind === "ready" && roster.items.length > 0 ? (
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
            <Badge variant={entry.state === "active" ? "secondary" : "outline"}>
              {entry.state}
            </Badge>
            <span>{entry.provenance.sourceKind.replaceAll("_", " ")}</span>
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
  ) : null;
}

function RosterRevokeForm({
  model,
}: {
  model: React.ComponentProps<typeof RosterRevokeAction>["model"];
}): React.ReactNode {
  const {
    epochId,
    id,
    isRevoking,
    mutationPending,
    revokeEntry,
    revokeReason,
    revokeReasonError,
    revokeRosterEntry,
    setRevokeEntryId,
    setRevokeReason,
    setRevokeReasonError,
  } = model;
  if (!revokeEntry) return null;
  return (
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
  );
}

interface RosterAddFormProps {
  addError: string | null;
  addReason: string;
  addReasonError: string | null;
  addRosterEntry: (event: React.FormEvent<HTMLFormElement>) => Promise<void>;
  expiresAt: string;
  expiresAtError: string | null;
  id: string;
  isAdding: boolean;
  memberId: string;
  model: React.ComponentProps<typeof EpochDetailView>["model"];
  mutationPending: boolean;
  setAddReason: (
    value: React.SetStateAction<EpochDetailState["addReason"]>,
  ) => void;
  setAddReasonError: (
    value: React.SetStateAction<EpochDetailState["addReasonError"]>,
  ) => void;
  setExpiresAt: (
    value: React.SetStateAction<EpochDetailState["expiresAt"]>,
  ) => void;
  setExpiresAtError: (
    value: React.SetStateAction<EpochDetailState["expiresAtError"]>,
  ) => void;
}

function RosterAddForm({
  addError,
  addReason,
  addReasonError,
  addRosterEntry,
  expiresAt,
  expiresAtError,
  id,
  isAdding,
  memberId,
  model,
  mutationPending,
  setAddReason,
  setAddReasonError,
  setExpiresAt,
  setExpiresAtError,
}: RosterAddFormProps): React.JSX.Element {
  return (
    <form className="roster-add-form" onSubmit={addRosterEntry}>
      {addError ? <FocusedError message={addError} /> : null}
      <RosterMembershipField model={model} />
      <RosterMembershipPagination model={model} />
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
  );
}

function RosterLoadError({
  model,
}: {
  model: React.ComponentProps<typeof EpochRoster>["model"];
}): React.ReactNode {
  const { canReadRoster, mutationPending, reloadRoster, roster } = model;
  return roster.kind === "error" ? (
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
  ) : null;
}
