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
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@periapsis/ui/components/ui/dialog";
import { Input } from "@periapsis/ui/components/ui/input";
import {
  Table,
  TableBody,
  TableCaption,
  TableCell,
  TableRow,
} from "@periapsis/ui/components/ui/table";
import { Textarea } from "@periapsis/ui/components/ui/textarea";
import {
  Archive,
  ArrowDown,
  CheckCircle2,
  Eye,
  Plus,
  RefreshCw,
  ShieldX,
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
import { z } from "zod";
import { TableColumnHeaders } from "../components/table-column-headers";
import { mergeOperatorTeams } from "./platform-operator-teams-model";
import { reduceWorkspaceState } from "./workspace-state";

import {
  usePlatformOperatorTeamCoordinator,
  type PlatformCreateMutationRequest,
  type PlatformDetailMutationRequest,
  type PlatformOperatorTeamMutationRequest,
} from "../auth/platform-operator-team-coordinator";
import { platformOperatorTeamMutationKey } from "../auth/platform-operator-team-keys";
import { useSession } from "../auth/session-context";
import { FocusedError } from "../components/focused-error";
import { FormField } from "../components/form-field";
import { readTextField } from "../lib/form-data";
import {
  describePhaseTwoError,
  hasPermission,
  PhaseTwoApiError,
  platformOperatorTeamManagePermission,
  platformOperatorTeamReadPermission,
  type OperatorTeamCreateInput,
  type OperatorTeamPatchInput,
  type OperatorTeamView,
  type VersionedView,
} from "../lib/phase-two-types";
import { hasControlCharacters } from "../lib/text-validation";

type TeamListState =
  | { kind: "error"; message: string }
  | {
      items: readonly OperatorTeamView[];
      kind: "ready";
      nextCursor?: string;
    }
  | { kind: "loading" };

type DetailState =
  | { kind: "error"; message: string }
  | { kind: "loading" }
  | { kind: "ready"; resource: VersionedView<OperatorTeamView> };

interface TeamDraft {
  description: string;
  name: string;
}

interface TouchedDraft {
  description: boolean;
  name: boolean;
}

type CreateMutationRequest = PlatformCreateMutationRequest;
type DetailMutationRequest = PlatformDetailMutationRequest;
type PlatformMutationRequest = PlatformOperatorTeamMutationRequest;

interface DetailReconciliation {
  id: number;
  sessionId: string;
  teamId: string;
  version: number;
}

interface TeamFieldErrors {
  description?: string;
  key?: string;
  name?: string;
}

interface CreateNotice {
  name: string;
  state: OperatorTeamView["state"];
}

const untouchedDraft: TouchedDraft = { description: false, name: false };

const teamDescriptionSchema = z
  .string()
  .max(500, "Use 500 characters or fewer.")
  .refine(
    (value) => !hasControlCharacters(value),
    "Use a description without control characters.",
  );

const teamNameSchema = z
  .string()
  .trim()
  .min(1, "Enter a team name.")
  .max(120, "Use 120 characters or fewer.")
  .refine(
    (value) => !hasControlCharacters(value),
    "Use a team name without control characters.",
  );

const createTeamSchema = z.object({
  description: teamDescriptionSchema,
  key: z
    .string()
    .trim()
    .toLowerCase()
    .regex(
      /^[a-z][a-z0-9_]{2,63}$/,
      "Use 3–64 lowercase letters, numbers, or underscores, starting with a letter.",
    ),
  name: teamNameSchema,
});

const teamMetadataSchema = z.object({
  description: teamDescriptionSchema,
  name: teamNameSchema,
});

const administrativeReasonSchema = z
  .string()
  .trim()
  .min(1, "Enter an administrative reason.")
  .max(500, "Use 500 characters or fewer.")
  .refine(
    (value) => !hasControlCharacters(value),
    "Use a reason without control characters.",
  );

export function PlatformOperatorTeamsPage(): React.JSX.Element {
  const model = usePlatformOperatorTeamsPageModel();
  if (model.kind === "content") return model.content;
  return <PlatformOperatorTeamsPageView model={model.data} />;
}

function usePlatformOperatorTeamsPageModel() {
  const { api, clearSession, session } = useSession();
  const {
    acknowledgeInventory,
    acknowledgeTeam,
    bindCreatePayload,
    clearCreateBindings,
    detachMutation,
    inventoryVersions,
    markMutationCommitted,
    registerMutation: registerPersistentMutation,
    releaseCreateBinding,
    revision: coordinatorRevision,
    settleMutation,
    teamVersion,
  } = usePlatformOperatorTeamCoordinator();
  const canRead = hasPermission(session, platformOperatorTeamReadPermission);
  const canManage = hasPermission(
    session,
    platformOperatorTeamManagePermission,
  );
  const [workspaceState, updateWorkspaceState] = useReducer(
    reduceWorkspaceState<PlatformOperatorTeamsPageState>,
    undefined,
    (): PlatformOperatorTeamsPageState => ({
      listState: {
        kind: "loading",
      },
      listRevision: 0,
      isLoadingMore: false,
      paginationError: null,
      createOpen: false,
      createError: null,
      createFieldErrors: {},
      isCreating: false,
      createNotice: null,
      selectedTeamId: null,
      detailReconciliation: null,
    }),
  );
  const {
    listState,
    listRevision,
    isLoadingMore,
    paginationError,
    createOpen,
    createError,
    createFieldErrors,
    isCreating,
    createNotice,
    selectedTeamId,
    detailReconciliation,
  } = workspaceState;
  const {
    setListState,
    setListRevision,
    setIsLoadingMore,
    setPaginationError,
    setCreateOpen,
    setCreateError,
    setCreateFieldErrors,
    setIsCreating,
    setSelectedTeamId,
    setDetailReconciliation,
  } = useMemo(
    () => ({
      setListState: (
        value: React.SetStateAction<
          PlatformOperatorTeamsPageState["listState"]
        >,
      ) => updateWorkspaceState({ listState: value }),
      setListRevision: (
        value: React.SetStateAction<
          PlatformOperatorTeamsPageState["listRevision"]
        >,
      ) => updateWorkspaceState({ listRevision: value }),
      setIsLoadingMore: (
        value: React.SetStateAction<
          PlatformOperatorTeamsPageState["isLoadingMore"]
        >,
      ) => updateWorkspaceState({ isLoadingMore: value }),
      setPaginationError: (
        value: React.SetStateAction<
          PlatformOperatorTeamsPageState["paginationError"]
        >,
      ) => updateWorkspaceState({ paginationError: value }),
      setCreateOpen: (
        value: React.SetStateAction<
          PlatformOperatorTeamsPageState["createOpen"]
        >,
      ) => updateWorkspaceState({ createOpen: value }),
      setCreateError: (
        value: React.SetStateAction<
          PlatformOperatorTeamsPageState["createError"]
        >,
      ) => updateWorkspaceState({ createError: value }),
      setCreateFieldErrors: (
        value: React.SetStateAction<
          PlatformOperatorTeamsPageState["createFieldErrors"]
        >,
      ) => updateWorkspaceState({ createFieldErrors: value }),
      setIsCreating: (
        value: React.SetStateAction<
          PlatformOperatorTeamsPageState["isCreating"]
        >,
      ) => updateWorkspaceState({ isCreating: value }),
      setSelectedTeamId: (
        value: React.SetStateAction<
          PlatformOperatorTeamsPageState["selectedTeamId"]
        >,
      ) => updateWorkspaceState({ selectedTeamId: value }),
      setDetailReconciliation: (
        value: React.SetStateAction<
          PlatformOperatorTeamsPageState["detailReconciliation"]
        >,
      ) => updateWorkspaceState({ detailReconciliation: value }),
    }),
    [updateWorkspaceState],
  );

  const sessionIdRef = useRef(session.id);
  const canReadRef = useRef(canRead);
  const canManageRef = useRef(canManage);
  const createGenerationRef = useRef(0);
  const createRequestRef = useRef<CreateMutationRequest | null>(null);
  const paginationCursorsRef = useRef<Set<string>>(new Set());
  const paginationRequestRef = useRef<AbortController | null>(null);
  const listRequestRef = useRef<AbortController | null>(null);
  const listReloadScheduledRef = useRef(false);
  const scheduledInventoryKeysRef = useRef<Set<string>>(new Set());
  const listReconcileKeysRef = useRef<Set<string>>(new Set());
  const failedInventoryReconciliationVersionsRef = useRef(
    new Map<string, number>(),
  );
  const failedTeamReconciliationVersionsRef = useRef(new Map<string, number>());
  const detailReconciliationSequenceRef = useRef(0);
  const detailReconciliationAttemptRef = useRef<DetailReconciliation | null>(
    null,
  );
  const pageMountedRef = useRef(false);
  const selectedTeamIdRef = useRef(selectedTeamId);
  const successRef = useRef<HTMLDivElement>(null);
  const id = useId();
  useLayoutEffect(() => {
    sessionIdRef.current = session.id;
    canReadRef.current = canRead;
    canManageRef.current = canManage;
    selectedTeamIdRef.current = selectedTeamId;
  }, [canManage, canRead, selectedTeamId, session]);

  const flushReconciliation = useCallback((): void => {
    if (!pageMountedRef.current || !canReadRef.current) {
      return;
    }

    if (!listRequestRef.current && !listReloadScheduledRef.current) {
      const eligibleKeys = new Set<string>();
      for (const [key, version] of inventoryVersions()) {
        if (
          failedInventoryReconciliationVersionsRef.current.get(key) !== version
        ) {
          eligibleKeys.add(key);
        }
      }
      if (eligibleKeys.size > 0) {
        listReloadScheduledRef.current = true;
        scheduledInventoryKeysRef.current = eligibleKeys;
        setListRevision((value) => value + 1);
      }
    }

    const selectedId = selectedTeamIdRef.current;
    if (!selectedId || detailReconciliationAttemptRef.current) return;
    const version = teamVersion(selectedId);
    if (
      version === undefined ||
      failedTeamReconciliationVersionsRef.current.get(selectedId) === version
    ) {
      return;
    }
    const attempt: DetailReconciliation = {
      id: detailReconciliationSequenceRef.current + 1,
      sessionId: sessionIdRef.current,
      teamId: selectedId,
      version,
    };
    detailReconciliationSequenceRef.current = attempt.id;
    detailReconciliationAttemptRef.current = attempt;
    setDetailReconciliation(attempt);
  }, [
    setListRevision,
    setDetailReconciliation,
    inventoryVersions,
    teamVersion,
  ]);

  const registerMutation = useCallback(
    (request: PlatformMutationRequest): boolean => {
      if (
        !pageMountedRef.current ||
        request.sessionId !== sessionIdRef.current ||
        (detailReconciliationAttemptRef.current?.teamId ===
          (request.kind === "create" ? null : request.teamId) &&
          request.kind !== "create") ||
        !registerPersistentMutation(request)
      ) {
        return false;
      }
      const key = platformOperatorTeamMutationKey(request);
      if (listReconcileKeysRef.current.has(key)) {
        listRequestRef.current?.abort();
        listRequestRef.current = null;
        listReconcileKeysRef.current.clear();
        flushReconciliation();
      }
      return true;
    },
    [flushReconciliation, registerPersistentMutation],
  );

  const acceptMutationRepresentation = useCallback(
    (request: DetailMutationRequest): void => {
      failedTeamReconciliationVersionsRef.current.delete(request.teamId);
    },
    [],
  );

  const settleDetailReconciliation = useCallback(
    (attempt: DetailReconciliation, succeeded: boolean): void => {
      if (
        detailReconciliationAttemptRef.current !== attempt ||
        attempt.sessionId !== sessionIdRef.current
      ) {
        return;
      }
      detailReconciliationAttemptRef.current = null;
      if (succeeded) {
        failedTeamReconciliationVersionsRef.current.delete(attempt.teamId);
        acknowledgeTeam(attempt.sessionId, attempt.teamId, attempt.version);
      } else {
        failedTeamReconciliationVersionsRef.current.set(
          attempt.teamId,
          attempt.version,
        );
      }
      flushReconciliation();
    },
    [acknowledgeTeam, flushReconciliation],
  );

  const abortDetailReconciliation = useCallback(
    (attempt: DetailReconciliation): void => {
      if (detailReconciliationAttemptRef.current !== attempt) return;
      detailReconciliationAttemptRef.current = null;
      queueMicrotask(flushReconciliation);
    },
    [flushReconciliation],
  );

  const retryDetailReconciliation = useCallback(
    (teamId: string): boolean => {
      if (
        selectedTeamIdRef.current !== teamId ||
        teamVersion(teamId) === undefined
      ) {
        return false;
      }
      failedTeamReconciliationVersionsRef.current.delete(teamId);
      flushReconciliation();
      return detailReconciliationAttemptRef.current?.teamId === teamId;
    },
    [flushReconciliation, teamVersion],
  );

  useEffect(() => {
    createGenerationRef.current += 1;
    updateWorkspaceState({
      createOpen: false,
      createError: null,
      createFieldErrors: {},
      createNotice: null,
      selectedTeamId: null,
      detailReconciliation: null,
      paginationError: null,
      isCreating: false,
    });
    createRequestRef.current = null;
    setIsLoadingMore(false);
    detailReconciliationAttemptRef.current = null;
    failedInventoryReconciliationVersionsRef.current.clear();
    failedTeamReconciliationVersionsRef.current.clear();
    paginationCursorsRef.current.clear();
  }, [setIsLoadingMore, session.id]);

  useEffect(() => {
    const request = createRequestRef.current;
    if (request) detachMutation(request);
    if (!canRead) detailReconciliationAttemptRef.current = null;
    createGenerationRef.current += 1;
    updateWorkspaceState({
      isCreating: false,
      createError: null,
      createFieldErrors: {},
    });
    createRequestRef.current = null;
    if (!canRead || !canManage) {
      clearCreateBindings(session.id);
      setCreateOpen(false);
    }
  }, [
    setCreateOpen,
    canManage,
    canRead,
    clearCreateBindings,
    detachMutation,
    session.id,
  ]);

  useEffect(() => {
    pageMountedRef.current = true;
    return () => {
      pageMountedRef.current = false;
      const request = createRequestRef.current;
      createGenerationRef.current += 1;
      createRequestRef.current = null;
      if (request) detachMutation(request);
      listRequestRef.current?.abort();
      paginationRequestRef.current?.abort();
    };
  }, [detachMutation]);

  useEffect(() => {
    flushReconciliation();
  }, [canRead, coordinatorRevision, flushReconciliation, selectedTeamId]);

  useEffect(() => {
    setPaginationError(null);
    paginationRequestRef.current?.abort();
    paginationRequestRef.current = null;
    setIsLoadingMore(false);
    listRequestRef.current?.abort();
    listRequestRef.current = null;
    const reconciliationWasScheduled = listReloadScheduledRef.current;
    listReloadScheduledRef.current = false;
    const availableVersions = inventoryVersions();
    const reconciliationVersions = new Map<string, number>();
    for (const key of new Set([
      ...scheduledInventoryKeysRef.current,
      ...availableVersions.keys(),
    ])) {
      const version = availableVersions.get(key);
      if (version !== undefined) {
        reconciliationVersions.set(key, version);
      }
    }
    scheduledInventoryKeysRef.current.clear();
    listReconcileKeysRef.current = new Set(reconciliationVersions.keys());
    if (!canRead) {
      listReconcileKeysRef.current.clear();
      return undefined;
    }
    if (reconciliationWasScheduled && reconciliationVersions.size === 0) {
      listReconcileKeysRef.current.clear();
      return undefined;
    }
    const controller = new AbortController();
    const requestedSessionId = session.id;
    let outcome: "aborted" | "failed" | "succeeded" = "failed";
    listRequestRef.current = controller;
    paginationCursorsRef.current.clear();
    setListState({ kind: "loading" });
    void api
      .listPlatformOperatorTeams({
        includeArchived: true,
        signal: controller.signal,
      })
      .then((page) => {
        if (
          controller.signal.aborted ||
          sessionIdRef.current !== requestedSessionId ||
          !pageMountedRef.current
        ) {
          return;
        }
        outcome = "succeeded";
        if (page.nextCursor) paginationCursorsRef.current.add(page.nextCursor);
        setListState({
          items: page.items,
          kind: "ready",
          ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
        });
      })
      .catch((caught: unknown) => {
        if (controller.signal.aborted || isAbortError(caught)) {
          outcome = "aborted";
          return;
        }
        if (caught instanceof PhaseTwoApiError && caught.status === 401) {
          clearSession(requestedSessionId);
          return;
        }
        setListState({
          kind: "error",
          message: describePhaseTwoError(
            caught,
            "The global operator-team inventory could not be loaded.",
          ),
        });
      })
      .finally(() => {
        if (listRequestRef.current !== controller) return;
        listRequestRef.current = null;
        listReconcileKeysRef.current.clear();
        if (
          controller.signal.aborted ||
          sessionIdRef.current !== requestedSessionId ||
          !pageMountedRef.current
        ) {
          return;
        }
        if (outcome === "succeeded") {
          for (const key of reconciliationVersions.keys()) {
            failedInventoryReconciliationVersionsRef.current.delete(key);
          }
          acknowledgeInventory(requestedSessionId, reconciliationVersions);
        } else {
          const currentVersions = inventoryVersions();
          for (const [key, version] of reconciliationVersions) {
            if (currentVersions.get(key) === version) {
              failedInventoryReconciliationVersionsRef.current.set(
                key,
                version,
              );
            }
          }
        }
        flushReconciliation();
      });
    return () => {
      controller.abort();
      if (listRequestRef.current === controller) {
        listRequestRef.current = null;
        listReconcileKeysRef.current.clear();
      }
    };
  }, [
    setPaginationError,
    setIsLoadingMore,
    setListState,
    api,
    acknowledgeInventory,
    canRead,
    clearSession,
    flushReconciliation,
    inventoryVersions,
    listRevision,
    session.id,
  ]);

  function dismissCreate(): void {
    const request = createRequestRef.current;
    createGenerationRef.current += 1;
    createRequestRef.current = null;
    updateWorkspaceState({
      createOpen: false,
      createError: null,
      createFieldErrors: {},
      isCreating: false,
    });
    if (request) detachMutation(request);
  }

  function createRequestIsCurrent(request: CreateMutationRequest): boolean {
    return (
      pageMountedRef.current &&
      createRequestRef.current === request &&
      createGenerationRef.current === request.generation &&
      sessionIdRef.current === request.sessionId &&
      canReadRef.current &&
      canManageRef.current
    );
  }

  function finishCreate(request: CreateMutationRequest): void {
    if (!createRequestIsCurrent(request)) return;
    createRequestRef.current = null;
    setIsCreating(false);
  }

  function openTeamDetail(teamId: string): void {
    detailReconciliationAttemptRef.current = null;
    selectedTeamIdRef.current = teamId;
    failedTeamReconciliationVersionsRef.current.delete(teamId);
    setSelectedTeamId(teamId);
    flushReconciliation();
  }

  function closeTeamDetail(): void {
    detailReconciliationAttemptRef.current = null;
    selectedTeamIdRef.current = null;
    setSelectedTeamId(null);
  }

  async function loadMore(): Promise<void> {
    if (
      listState.kind !== "ready" ||
      !listState.nextCursor ||
      isLoadingMore ||
      paginationRequestRef.current
    ) {
      return;
    }
    const requestedCursor = listState.nextCursor;
    const requestedSessionId = session.id;
    const controller = new AbortController();
    paginationRequestRef.current = controller;
    updateWorkspaceState({ isLoadingMore: true, paginationError: null });
    try {
      const page = await api.listPlatformOperatorTeams({
        after: requestedCursor,
        includeArchived: true,
        signal: controller.signal,
      });
      if (
        controller.signal.aborted ||
        sessionIdRef.current !== requestedSessionId
      )
        return;
      if (page.nextCursor === requestedCursor) {
        throw new Error("The operator-team cursor did not advance.");
      }
      if (
        page.nextCursor &&
        paginationCursorsRef.current.has(page.nextCursor)
      ) {
        throw new Error("The operator-team cursor entered a cycle.");
      }
      if (page.nextCursor) paginationCursorsRef.current.add(page.nextCursor);
      setListState((current) =>
        current.kind === "ready" && current.nextCursor === requestedCursor
          ? {
              items: mergeOperatorTeams(current.items, page.items),
              kind: "ready",
              ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
            }
          : current,
      );
    } catch (caught) {
      if (
        controller.signal.aborted ||
        sessionIdRef.current !== requestedSessionId ||
        isAbortError(caught)
      )
        return;
      if (caught instanceof PhaseTwoApiError && caught.status === 401) {
        clearSession(requestedSessionId);
        return;
      }
      setPaginationError(
        describePhaseTwoError(
          caught,
          "The next operator-team page could not be loaded.",
        ),
      );
    } finally {
      if (paginationRequestRef.current === controller) {
        paginationRequestRef.current = null;
      }
      // react-doctor-disable-next-line no-loading-flag-reset-outside-finally -- The owning request clears this flag in finally; the generation guard protects newer requests.
      if (sessionIdRef.current === requestedSessionId) setIsLoadingMore(false);
    }
  }

  async function createTeam(
    event: React.FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault();
    if (!canReadRef.current || !canManageRef.current) {
      dismissCreate();
      return;
    }
    if (createRequestRef.current) return;
    const form = event.currentTarget;
    const data = new FormData(form);
    const parsed = createTeamSchema.safeParse({
      description: readTextField(data, "description"),
      key: readTextField(data, "key"),
      name: readTextField(data, "name"),
    });
    if (!parsed.success) {
      updateWorkspaceState({
        createError: null,
        createFieldErrors: teamFieldErrors(parsed.error),
      });
      return;
    }
    const description = parsed.data.description.trim();
    const input: OperatorTeamCreateInput = {
      key: parsed.data.key,
      name: parsed.data.name,
      ...(description ? { description } : {}),
    };
    const expectedSessionId = session.id;
    const idempotencyPayload = {
      input,
      operation: "platform.operator-team.create",
    };
    const { binding, key: idempotencyKey } =
      bindCreatePayload(idempotencyPayload);
    const requestedGeneration = createGenerationRef.current + 1;
    createGenerationRef.current = requestedGeneration;
    const request: CreateMutationRequest = {
      binding,
      generation: requestedGeneration,
      kind: "create",
      sessionId: expectedSessionId,
    };
    if (!registerMutation(request)) return;
    createRequestRef.current = request;
    updateWorkspaceState({
      createError: null,
      createFieldErrors: {},
      isCreating: true,
    });
    try {
      const created = await api.createPlatformOperatorTeam(
        session.csrfToken,
        idempotencyKey,
        input,
      );
      markMutationCommitted(request);
      releaseCreateBinding(request);
      if (!createRequestIsCurrent(request)) {
        return;
      }
      updateWorkspaceState({
        listState: (current) =>
          current.kind === "ready"
            ? {
                ...current,
                items: mergeOperatorTeams([created.value], current.items),
              }
            : current,
        createOpen: false,
        createNotice: {
          name: created.value.name,
          state: created.value.state,
        },
      });
      requestAnimationFrame(() => successRef.current?.focus());
    } catch (caught) {
      if (!createRequestIsCurrent(request)) return;
      if (caught instanceof PhaseTwoApiError && caught.status === 401) {
        clearSession(expectedSessionId);
        return;
      }
      setCreateError(
        describePhaseTwoError(
          caught,
          "The operator-team identity was not created. The same payload can be retried safely.",
        ),
      );
    } finally {
      finishCreate(request);
      settleMutation(request);
    }
  }

  if (!canRead) {
    return { kind: "content" as const, content: <PlatformTeamDenied /> };
  }

  return {
    kind: "ready" as const,
    data: {
      abortDetailReconciliation,
      acceptMutationRepresentation,
      canManage,
      closeTeamDetail,
      createError,
      createFieldErrors,
      createNotice,
      createOpen,
      createTeam,
      detachMutation,
      detailReconciliation,
      dismissCreate,
      id,
      isCreating,
      isLoadingMore,
      listState,
      loadMore,
      markMutationCommitted,
      openTeamDetail,
      paginationError,
      registerMutation,
      retryDetailReconciliation,
      selectedTeamId,
      session,
      setCreateError,
      setCreateFieldErrors,
      setCreateOpen,
      setListRevision,
      setListState,
      settleDetailReconciliation,
      settleMutation,
      successRef,
    },
  };
}

function PlatformOperatorTeamsPageView({
  model,
}: {
  model: Extract<
    ReturnType<typeof usePlatformOperatorTeamsPageModel>,
    { kind: "ready" }
  >["data"];
}): React.JSX.Element {
  const { createNotice, successRef } = model;
  return (
    <div className="content operator-team-page platform-operator-team-page">
      <section className="page-heading" aria-labelledby="platform-team-title">
        <div>
          <p className="section-label">Platform administration</p>
          <h1 id="platform-team-title">Operator-team identities</h1>
          <p>
            Govern the global work-queue identities used by tenant assignment
            epochs. A team has no tenant authority until a tenant starts an
            explicit epoch and builds its exact roster.
          </p>
        </div>
        <Badge variant="outline">
          <UsersRound aria-hidden="true" /> Global identity plane
        </Badge>
      </section>

      {createNotice ? (
        <Alert
          ref={successRef}
          tabIndex={-1}
          className={
            createNotice.state === "active" ? "success-alert" : undefined
          }
        >
          {createNotice.state === "archived" ? (
            <Archive aria-hidden="true" />
          ) : (
            <CheckCircle2 aria-hidden="true" />
          )}
          <AlertTitle>
            {createNotice.state === "archived"
              ? "Operator team is archived"
              : "Operator team created"}
          </AlertTitle>
          <AlertDescription>
            {createNotice.state === "archived"
              ? `${createNotice.name} is historical and is not available for tenant assignment.`
              : `${createNotice.name} is available for explicit tenant assignment.`}
          </AlertDescription>
        </Alert>
      ) : null}

      <OperatorTeamInventory model={model} />

      <OperatorTeamCreatePanel model={model} />

      {<SelectedOperatorTeamDetail model={model} />}
    </div>
  );
}

function OperatorTeamDetail(props: {
  canManage: boolean;
  onAcceptMutationRepresentation: (request: DetailMutationRequest) => void;
  onAbortReconciliation: (attempt: DetailReconciliation) => void;
  onArchived: () => void;
  onChanged: (team: OperatorTeamView) => void;
  onClose: () => void;
  onDetachMutation: (request: DetailMutationRequest) => void;
  onMutationCommitted: (request: DetailMutationRequest) => void;
  onRegisterMutation: (request: DetailMutationRequest) => boolean;
  onRetryReconciliation: (teamId: string) => boolean;
  onSettleMutation: (request: DetailMutationRequest) => void;
  onSettleReconciliation: (
    attempt: DetailReconciliation,
    succeeded: boolean,
  ) => void;
  reconciliation: DetailReconciliation | undefined;
  teamId: string;
}): React.JSX.Element {
  const model = useOperatorTeamDetailModel(props);
  return <OperatorTeamDetailView model={model.data} />;
}

function useOperatorTeamDetailModel({
  canManage,
  onAcceptMutationRepresentation,
  onAbortReconciliation,
  onArchived,
  onChanged,
  onClose,
  onDetachMutation,
  onMutationCommitted,
  onRegisterMutation,
  onRetryReconciliation,
  onSettleMutation,
  onSettleReconciliation,
  reconciliation,
  teamId,
}: {
  canManage: boolean;
  onAcceptMutationRepresentation: (request: DetailMutationRequest) => void;
  onAbortReconciliation: (attempt: DetailReconciliation) => void;
  onArchived: () => void;
  onChanged: (team: OperatorTeamView) => void;
  onClose: () => void;
  onDetachMutation: (request: DetailMutationRequest) => void;
  onMutationCommitted: (request: DetailMutationRequest) => void;
  onRegisterMutation: (request: DetailMutationRequest) => boolean;
  onRetryReconciliation: (teamId: string) => boolean;
  onSettleMutation: (request: DetailMutationRequest) => void;
  onSettleReconciliation: (
    attempt: DetailReconciliation,
    succeeded: boolean,
  ) => void;
  reconciliation: DetailReconciliation | undefined;
  teamId: string;
}) {
  const { api, clearSession, session } = useSession();
  const [workspaceState, updateWorkspaceState] = useReducer(
    reduceWorkspaceState<OperatorTeamDetailState>,
    undefined,
    (): OperatorTeamDetailState => ({
      detail: { kind: "loading" },
      revision: 0,
      draft: { description: "", name: "" },
      touched: untouchedDraft,
      fieldErrors: {},
      mutationError: null,
      stale: false,
      isSaving: false,
      archiveReason: "",
      archiveReasonError: null,
      isArchiving: false,
    }),
  );
  const {
    detail,
    revision,
    draft,
    touched,
    fieldErrors,
    mutationError,
    stale,
    isSaving,
    archiveReason,
    archiveReasonError,
    isArchiving,
  } = workspaceState;
  const {
    setDetail,
    setRevision,
    setDraft,
    setTouched,
    setFieldErrors,
    setIsSaving,
    setArchiveReason,
    setArchiveReasonError,
    setIsArchiving,
  } = useMemo(
    () => ({
      setDetail: (
        value: React.SetStateAction<OperatorTeamDetailState["detail"]>,
      ) => updateWorkspaceState({ detail: value }),
      setRevision: (
        value: React.SetStateAction<OperatorTeamDetailState["revision"]>,
      ) => updateWorkspaceState({ revision: value }),
      setDraft: (
        value: React.SetStateAction<OperatorTeamDetailState["draft"]>,
      ) => updateWorkspaceState({ draft: value }),
      setTouched: (
        value: React.SetStateAction<OperatorTeamDetailState["touched"]>,
      ) => updateWorkspaceState({ touched: value }),
      setFieldErrors: (
        value: React.SetStateAction<OperatorTeamDetailState["fieldErrors"]>,
      ) => updateWorkspaceState({ fieldErrors: value }),
      setIsSaving: (
        value: React.SetStateAction<OperatorTeamDetailState["isSaving"]>,
      ) => updateWorkspaceState({ isSaving: value }),
      setArchiveReason: (
        value: React.SetStateAction<OperatorTeamDetailState["archiveReason"]>,
      ) => updateWorkspaceState({ archiveReason: value }),
      setArchiveReasonError: (
        value: React.SetStateAction<
          OperatorTeamDetailState["archiveReasonError"]
        >,
      ) => updateWorkspaceState({ archiveReasonError: value }),
      setIsArchiving: (
        value: React.SetStateAction<OperatorTeamDetailState["isArchiving"]>,
      ) => updateWorkspaceState({ isArchiving: value }),
    }),
    [updateWorkspaceState],
  );

  const mountedRef = useRef(false);
  const canManageRef = useRef(canManage);
  const manageGenerationRef = useRef(0);
  const mutationRequestRef = useRef<DetailMutationRequest | null>(null);
  const sessionIdRef = useRef(session.id);
  const teamIdRef = useRef(teamId);
  const draftRef = useRef(draft);
  const serverDraftRef = useRef<TeamDraft>({ description: "", name: "" });
  const touchedRef = useRef(touched);
  const id = useId();
  useLayoutEffect(() => {
    canManageRef.current = canManage;
    sessionIdRef.current = session.id;
    teamIdRef.current = teamId;
    draftRef.current = draft;
    touchedRef.current = touched;
  }, [canManage, draft, session, teamId, touched]);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      const request = mutationRequestRef.current;
      mutationRequestRef.current = null;
      if (request) onDetachMutation(request);
    };
  }, [onDetachMutation]);

  useEffect(() => {
    const request = mutationRequestRef.current;
    if (request) onDetachMutation(request);
    manageGenerationRef.current += 1;
    mutationRequestRef.current = null;
    const currentDraft = serverDraftRef.current;
    draftRef.current = currentDraft;
    touchedRef.current = untouchedDraft;
    updateWorkspaceState({
      draft: currentDraft,
      touched: untouchedDraft,
      fieldErrors: {},
      archiveReason: "",
      archiveReasonError: null,
      mutationError: null,
      stale: false,
      isSaving: false,
      isArchiving: false,
    });
  }, [canManage, onDetachMutation, session.id, teamId]);

  function beginMutation(
    kind: DetailMutationRequest["kind"],
  ): DetailMutationRequest | null {
    if (mutationRequestRef.current) return null;
    const request: DetailMutationRequest = {
      generation: manageGenerationRef.current,
      kind,
      sessionId: session.id,
      teamId,
    };
    if (!onRegisterMutation(request)) return null;
    mutationRequestRef.current = request;
    return request;
  }

  function mutationIsCurrent(request: DetailMutationRequest): boolean {
    return (
      mountedRef.current &&
      canManageRef.current &&
      mutationRequestRef.current === request &&
      manageGenerationRef.current === request.generation &&
      sessionIdRef.current === request.sessionId &&
      teamIdRef.current === request.teamId
    );
  }

  function finishMutation(request: DetailMutationRequest): void {
    if (!mutationIsCurrent(request)) return;
    mutationRequestRef.current = null;
    if (request.kind === "save") setIsSaving(false);
    else setIsArchiving(false);
  }

  function dismissDetail(): void {
    const request = mutationRequestRef.current;
    manageGenerationRef.current += 1;
    mutationRequestRef.current = null;
    if (request) onDetachMutation(request);
    onClose();
  }

  useEffect(() => {
    const controller = new AbortController();
    const reconciliationAttempt =
      reconciliation?.sessionId === session.id &&
      reconciliation.teamId === teamId
        ? reconciliation
        : null;
    setDetail({ kind: "loading" });
    void api
      .getPlatformOperatorTeam(teamId, controller.signal)
      .then((resource) => {
        if (controller.signal.aborted) return;
        serverDraftRef.current = {
          description: resource.value.description,
          name: resource.value.name,
        };
        updateWorkspaceState({
          detail: { kind: "ready", resource },
          draft: {
            description: touchedRef.current.description
              ? draftRef.current.description
              : resource.value.description,
            name: touchedRef.current.name
              ? draftRef.current.name
              : resource.value.name,
          },
          mutationError: null,
          stale: false,
        });
        if (reconciliationAttempt) {
          onSettleReconciliation(reconciliationAttempt, true);
        }
      })
      .catch((caught: unknown) => {
        if (controller.signal.aborted || isAbortError(caught)) return;
        if (caught instanceof PhaseTwoApiError && caught.status === 401) {
          clearSession(session.id);
          return;
        }
        setDetail({
          kind: "error",
          message: describePhaseTwoError(
            caught,
            "The current operator-team representation could not be loaded.",
          ),
        });
        if (reconciliationAttempt) {
          onSettleReconciliation(reconciliationAttempt, false);
        }
      });
    return () => {
      controller.abort();
      if (reconciliationAttempt) {
        onAbortReconciliation(reconciliationAttempt);
      }
    };
  }, [
    setDetail,
    api,
    clearSession,
    onAbortReconciliation,
    onSettleReconciliation,
    reconciliation,
    revision,
    session.id,
    teamId,
  ]);

  async function save(event: React.FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (!canManageRef.current || detail.kind !== "ready") return;
    const parsed = teamMetadataSchema.safeParse(draft);
    if (!parsed.success) {
      updateWorkspaceState({
        mutationError: null,
        stale: false,
        fieldErrors: teamFieldErrors(parsed.error),
      });
      return;
    }
    const input: OperatorTeamPatchInput = {
      ...(touched.name ? { name: parsed.data.name } : {}),
      ...(touched.description
        ? { description: parsed.data.description.trim() }
        : {}),
    };
    if (Object.keys(input).length === 0) return;
    const request = beginMutation("save");
    if (!request) return;
    updateWorkspaceState({
      mutationError: null,
      fieldErrors: {},
      isSaving: true,
    });
    try {
      const updated = await api.updatePlatformOperatorTeam(
        session.csrfToken,
        teamId,
        detail.resource.etag,
        input,
      );
      onMutationCommitted(request);
      if (!mutationIsCurrent(request)) {
        return;
      }
      serverDraftRef.current = {
        description: updated.value.description,
        name: updated.value.name,
      };
      updateWorkspaceState({
        detail: { kind: "ready", resource: updated },
        draft: {
          description: updated.value.description,
          name: updated.value.name,
        },
        touched: untouchedDraft,
        fieldErrors: {},
        stale: false,
      });
      onAcceptMutationRepresentation(request);
      onChanged(updated.value);
    } catch (caught) {
      if (!mutationIsCurrent(request)) return;
      if (caught instanceof PhaseTwoApiError && caught.status === 401) {
        clearSession(session.id);
        return;
      }
      updateWorkspaceState({
        stale: caught instanceof PhaseTwoApiError && caught.status === 412,
        mutationError: describePhaseTwoError(
          caught,
          "The team metadata was not saved.",
        ),
      });
    } finally {
      // react-doctor-disable-next-line no-loading-flag-reset-outside-finally -- The owning request clears this flag in finally; the generation guard protects newer requests.
      finishMutation(request);
      onSettleMutation(request);
    }
  }

  async function archive(): Promise<void> {
    if (!canManageRef.current || detail.kind !== "ready") return;
    const parsedReason = administrativeReasonSchema.safeParse(archiveReason);
    if (!parsedReason.success) {
      updateWorkspaceState({
        mutationError: null,
        stale: false,
        archiveReasonError:
          parsedReason.error.issues[0]?.message ??
          "Enter an administrative reason.",
      });
      return;
    }
    const request = beginMutation("archive");
    if (!request) return;
    updateWorkspaceState({
      mutationError: null,
      archiveReasonError: null,
      isArchiving: true,
    });
    try {
      await api.archivePlatformOperatorTeam(
        session.csrfToken,
        teamId,
        detail.resource.etag,
        { reason: parsedReason.data },
      );
      onMutationCommitted(request);
      if (!mutationIsCurrent(request)) {
        return;
      }
      onArchived();
    } catch (caught) {
      if (!mutationIsCurrent(request)) return;
      if (caught instanceof PhaseTwoApiError && caught.status === 401) {
        clearSession(session.id);
        return;
      }
      updateWorkspaceState({
        stale: caught instanceof PhaseTwoApiError && caught.status === 412,
        mutationError: describePhaseTwoError(
          caught,
          "The team was not archived. End every active tenant epoch first.",
        ),
      });
    } finally {
      finishMutation(request);
      onSettleMutation(request);
    }
  }

  return {
    kind: "ready" as const,
    data: {
      archive,
      archiveReason,
      archiveReasonError,
      canManage,
      detail,
      dismissDetail,
      draft,
      fieldErrors,
      id,
      isArchiving,
      isSaving,
      mutationError,
      onRetryReconciliation,
      save,
      setArchiveReason,
      setArchiveReasonError,
      setDraft,
      setFieldErrors,
      setRevision,
      setTouched,
      stale,
      teamId,
      touched,
    },
  };
}

function OperatorTeamDetailView({
  model,
}: {
  model: Extract<
    ReturnType<typeof useOperatorTeamDetailModel>,
    { kind: "ready" }
  >["data"];
}): React.JSX.Element {
  return <OperatorTeamDetailContent model={model} />;
}

function PlatformTeamDenied(): React.JSX.Element {
  return (
    <div className="content content--narrow">
      <section
        className="page-heading"
        aria-labelledby="platform-team-denied-title"
      >
        <div>
          <p className="section-label">Platform administration</p>
          <h1 id="platform-team-denied-title">
            Operator teams are not available.
          </h1>
          <p>
            The current session did not return explicit platform operator-team
            read authority.
          </p>
        </div>
      </section>
      <Alert variant="destructive">
        <ShieldX aria-hidden="true" />
        <AlertTitle>Permission not returned</AlertTitle>
        <AlertDescription>
          Tenant authority never grants access to the global team catalog.
        </AlertDescription>
      </Alert>
    </div>
  );
}

function OperatorTeamSkeleton(): React.JSX.Element {
  return (
    <div
      className="operator-team-list-skeleton"
      aria-label="Loading operator teams"
    >
      <span />
      <span />
      <span />
    </div>
  );
}

function OperatorTeamDetailSkeleton(): React.JSX.Element {
  return (
    <div
      className="operator-team-detail-skeleton"
      aria-label="Loading operator-team detail"
    >
      <span />
      <span />
      <span />
    </div>
  );
}

function teamFieldErrors(error: z.ZodError): TeamFieldErrors {
  const errors: TeamFieldErrors = {};
  for (const issue of error.issues) {
    const field = issue.path[0];
    if (
      (field === "description" || field === "key" || field === "name") &&
      errors[field] === undefined
    ) {
      errors[field] = issue.message;
    }
  }
  return errors;
}

function withoutTeamFieldError(
  errors: TeamFieldErrors,
  field: keyof TeamFieldErrors,
): TeamFieldErrors {
  if (errors[field] === undefined) return errors;
  const remaining = { ...errors };
  delete remaining[field];
  return remaining;
}

function formatDateTime(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function isAbortError(error: unknown): boolean {
  return error instanceof DOMException && error.name === "AbortError";
}

function OperatorTeamInventory({
  model,
}: {
  model: React.ComponentProps<typeof PlatformOperatorTeamsPageView>["model"];
}): React.ReactNode {
  const { isLoadingMore, listState, loadMore, paginationError } = model;
  return (
    <section
      className="operator-team-inventory"
      aria-labelledby="team-inventory-title"
    >
      <OperatorTeamInventoryHeading model={model} />

      {listState.kind === "loading" ? <OperatorTeamSkeleton /> : null}
      {listState.kind === "error" ? (
        <FocusedError message={listState.message} />
      ) : null}
      {paginationError ? (
        <FocusedError
          title="More operator teams could not be loaded"
          message={paginationError}
        />
      ) : null}
      {listState.kind === "ready" && listState.items.length === 0 ? (
        <div className="operator-team-empty">
          <UsersRound aria-hidden="true" />
          <h3>No global teams yet</h3>
          <p>
            Create the first queue identity before assigning it to a tenant.
          </p>
        </div>
      ) : null}
      {<OperatorTeamInventoryTable model={model} />}
      {listState.kind === "ready" && listState.nextCursor ? (
        <Button
          type="button"
          variant="outline"
          disabled={isLoadingMore}
          onClick={() => void loadMore()}
        >
          <ArrowDown aria-hidden="true" />
          {isLoadingMore ? "Loading teams…" : "Load more operator teams"}
        </Button>
      ) : null}
    </section>
  );
}

function OperatorTeamCreatePanel({
  model,
}: {
  model: React.ComponentProps<typeof PlatformOperatorTeamsPageView>["model"];
}): React.ReactNode {
  const { canManage, createOpen, dismissCreate, setCreateOpen } = model;
  return (
    <Dialog
      open={createOpen && canManage}
      onOpenChange={(open) => {
        if (!open) dismissCreate();
        else if (canManage) setCreateOpen(true);
      }}
    >
      <OperatorTeamCreateDialog model={model} />
    </Dialog>
  );
}

function OperatorTeamDetailContent({
  model,
}: {
  model: React.ComponentProps<typeof OperatorTeamDetailView>["model"];
}): React.ReactNode {
  const {
    detail,
    dismissDetail,
    mutationError,
    onRetryReconciliation,
    setRevision,
    stale,
    teamId,
  } = model;
  return (
    <Dialog
      open
      onOpenChange={(open) => {
        if (!open) dismissDetail();
      }}
    >
      <DialogContent className="operator-team-detail-dialog">
        <DialogHeader>
          <DialogTitle>
            {detail.kind === "ready"
              ? `Operator team · ${detail.resource.value.name}`
              : "Operator-team detail"}
          </DialogTitle>
          <DialogDescription>
            Global metadata and lifecycle. Tenant epochs and rosters remain
            separate tenant-owned records.
          </DialogDescription>
        </DialogHeader>
        {detail.kind === "loading" ? <OperatorTeamDetailSkeleton /> : null}
        {detail.kind === "error" ? (
          <div className="operator-team-detail-error">
            <FocusedError message={detail.message} />
            <Button
              type="button"
              variant="outline"
              onClick={() => {
                if (!onRetryReconciliation(teamId)) {
                  setRevision((value) => value + 1);
                }
              }}
            >
              <RefreshCw aria-hidden="true" /> Retry team detail
            </Button>
          </div>
        ) : null}
        {detail.kind === "ready" ? (
          <div className="operator-team-detail-ready">
            <dl className="operator-team-facts">
              <div>
                <dt>Immutable key</dt>
                <dd>{detail.resource.value.key}</dd>
              </div>
              <div>
                <dt>Version</dt>
                <dd>
                  <code>{detail.resource.etag}</code>
                </dd>
              </div>
              <div>
                <dt>Lifecycle</dt>
                <dd>{detail.resource.value.state}</dd>
              </div>
              <div>
                <dt>Active epochs</dt>
                <dd>{detail.resource.value.activeAssignmentCount}</dd>
              </div>
            </dl>
            {mutationError ? (
              <div className="operator-team-stale-block">
                <FocusedError
                  message={mutationError}
                  title={
                    stale ? "Server version changed" : "Team action failed"
                  }
                />
                {stale ? (
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => {
                      if (!onRetryReconciliation(teamId)) {
                        setRevision((value) => value + 1);
                      }
                    }}
                  >
                    <RefreshCw aria-hidden="true" /> Load current version
                  </Button>
                ) : null}
              </div>
            ) : null}
            <OperatorTeamMetadataForm model={model} />
            {<OperatorTeamArchivePanel model={model} />}
          </div>
        ) : null}
        <DialogFooter>
          <Button type="button" variant="outline" onClick={dismissDetail}>
            Close
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

interface PlatformOperatorTeamsPageState {
  listState: TeamListState;
  listRevision: number;
  isLoadingMore: boolean;
  paginationError: string | null;
  createOpen: boolean;
  createError: string | null;
  createFieldErrors: TeamFieldErrors;
  isCreating: boolean;
  createNotice: CreateNotice | null;
  selectedTeamId: string | null;
  detailReconciliation: DetailReconciliation | null;
}

interface OperatorTeamDetailState {
  detail: DetailState;
  revision: number;
  draft: TeamDraft;
  touched: TouchedDraft;
  fieldErrors: TeamFieldErrors;
  mutationError: string | null;
  stale: boolean;
  isSaving: boolean;
  archiveReason: string;
  archiveReasonError: string | null;
  isArchiving: boolean;
}

function SelectedOperatorTeamDetail({
  model,
}: {
  model: React.ComponentProps<typeof PlatformOperatorTeamsPageView>["model"];
}): React.ReactNode {
  const {
    abortDetailReconciliation,
    acceptMutationRepresentation,
    canManage,
    closeTeamDetail,
    detachMutation,
    detailReconciliation,
    markMutationCommitted,
    registerMutation,
    retryDetailReconciliation,
    selectedTeamId,
    session,
    setListRevision,
    setListState,
    settleDetailReconciliation,
    settleMutation,
  } = model;
  return selectedTeamId ? (
    <OperatorTeamDetail
      key={`${session.id}:${selectedTeamId}`}
      teamId={selectedTeamId}
      canManage={canManage}
      reconciliation={
        detailReconciliation?.teamId === selectedTeamId
          ? detailReconciliation
          : undefined
      }
      onAbortReconciliation={abortDetailReconciliation}
      onAcceptMutationRepresentation={acceptMutationRepresentation}
      onClose={closeTeamDetail}
      onDetachMutation={detachMutation}
      onChanged={(team) => {
        setListState((current) =>
          current.kind === "ready"
            ? {
                ...current,
                items: mergeOperatorTeams(current.items, [team]),
              }
            : current,
        );
      }}
      onArchived={() => {
        closeTeamDetail();
        setListRevision((value) => value + 1);
      }}
      onMutationCommitted={markMutationCommitted}
      onRegisterMutation={registerMutation}
      onRetryReconciliation={retryDetailReconciliation}
      onSettleMutation={settleMutation}
      onSettleReconciliation={settleDetailReconciliation}
    />
  ) : null;
}

function OperatorTeamInventoryHeading({
  model,
}: {
  model: React.ComponentProps<typeof OperatorTeamInventory>["model"];
}): React.ReactNode {
  const {
    canManage,
    listState,
    setCreateError,
    setCreateFieldErrors,
    setCreateOpen,
    setListRevision,
  } = model;
  return (
    <div className="operator-team-section-heading">
      <div>
        <p className="section-label">Global catalog</p>
        <h2 id="team-inventory-title">Work-queue identities</h2>
      </div>
      <div className="operator-team-heading-actions">
        {listState.kind === "error" ? (
          <Button
            type="button"
            variant="outline"
            onClick={() => setListRevision((value) => value + 1)}
          >
            <RefreshCw aria-hidden="true" /> Retry
          </Button>
        ) : null}
        {canManage ? (
          <Button
            type="button"
            onClick={() => {
              setCreateError(null);
              setCreateFieldErrors({});
              setCreateOpen(true);
            }}
          >
            <Plus aria-hidden="true" /> Create operator team
          </Button>
        ) : null}
      </div>
    </div>
  );
}

function OperatorTeamInventoryTable({
  model,
}: {
  model: React.ComponentProps<typeof OperatorTeamInventory>["model"];
}): React.ReactNode {
  const { listState, openTeamDetail } = model;
  return listState.kind === "ready" && listState.items.length > 0 ? (
    <Card className="operator-team-table-card">
      <CardContent>
        <Table className="operator-team-table">
          <TableCaption className="sr-only">
            Global operator-team identities
          </TableCaption>
          <TableColumnHeaders
            columns={["Team", "Lifecycle", "Active tenant epochs", "Updated"]}
            actionLabel="Actions"
          />
          <TableBody>
            {listState.items.map((team) => (
              <TableRow key={team.id}>
                <TableCell>
                  <span className="operator-team-name-cell">
                    <strong>{team.name}</strong>
                    <small>{team.key}</small>
                  </span>
                </TableCell>
                <TableCell>
                  <Badge
                    variant={team.state === "active" ? "secondary" : "outline"}
                  >
                    {team.state}
                  </Badge>
                </TableCell>
                <TableCell>
                  <span className="operator-team-count">
                    {team.activeAssignmentCount}
                  </span>
                </TableCell>
                <TableCell>{formatDateTime(team.updatedAt)}</TableCell>
                <TableCell>
                  <Button
                    type="button"
                    size="sm"
                    variant="ghost"
                    aria-label={`Open ${team.name} (${team.key})`}
                    onClick={() => openTeamDetail(team.id)}
                  >
                    <Eye aria-hidden="true" /> Open
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  ) : null;
}

function OperatorTeamCreateDialog({
  model,
}: {
  model: React.ComponentProps<typeof OperatorTeamCreatePanel>["model"];
}): React.ReactNode {
  const {
    createError,
    createFieldErrors,
    createTeam,
    dismissCreate,
    id,
    isCreating,
    setCreateFieldErrors,
  } = model;
  return (
    <DialogContent className="operator-team-create-dialog">
      <DialogHeader>
        <DialogTitle>Create operator team</DialogTitle>
        <DialogDescription>
          The immutable key identifies this team across tenant epoch history.
          Creation alone grants no tenant access.
        </DialogDescription>
      </DialogHeader>
      <form className="operator-team-form" onSubmit={createTeam} noValidate>
        {createError ? <FocusedError message={createError} /> : null}
        <FormField
          htmlFor={`${id}-team-key`}
          label="Immutable key"
          hint="Lowercase letters, numbers, and underscores; for example soc_l2."
          {...(createFieldErrors.key ? { error: createFieldErrors.key } : {})}
        >
          <Input
            id={`${id}-team-key`}
            name="key"
            required
            minLength={3}
            maxLength={64}
            pattern="[a-z][a-z0-9_]{1,63}"
            disabled={isCreating}
            aria-invalid={createFieldErrors.key ? "true" : undefined}
            aria-describedby={`${id}-team-key-${createFieldErrors.key ? "error" : "hint"}`}
            onChange={() =>
              setCreateFieldErrors((current) =>
                withoutTeamFieldError(current, "key"),
              )
            }
          />
        </FormField>
        <FormField
          htmlFor={`${id}-team-name`}
          label="Team name"
          {...(createFieldErrors.name ? { error: createFieldErrors.name } : {})}
        >
          <Input
            id={`${id}-team-name`}
            name="name"
            required
            maxLength={120}
            disabled={isCreating}
            aria-invalid={createFieldErrors.name ? "true" : undefined}
            aria-describedby={
              createFieldErrors.name ? `${id}-team-name-error` : undefined
            }
            onChange={() =>
              setCreateFieldErrors((current) =>
                withoutTeamFieldError(current, "name"),
              )
            }
          />
        </FormField>
        <FormField
          htmlFor={`${id}-team-description`}
          label="Description"
          optional
          {...(createFieldErrors.description
            ? { error: createFieldErrors.description }
            : {})}
        >
          <Textarea
            id={`${id}-team-description`}
            name="description"
            maxLength={500}
            disabled={isCreating}
            aria-invalid={createFieldErrors.description ? "true" : undefined}
            aria-describedby={
              createFieldErrors.description
                ? `${id}-team-description-error`
                : undefined
            }
            onChange={() =>
              setCreateFieldErrors((current) =>
                withoutTeamFieldError(current, "description"),
              )
            }
          />
        </FormField>
        <DialogFooter>
          <Button type="button" variant="outline" onClick={dismissCreate}>
            Cancel
          </Button>
          <Button type="submit" disabled={isCreating}>
            <Plus aria-hidden="true" />
            {isCreating ? "Creating team…" : "Create operator team"}
          </Button>
        </DialogFooter>
      </form>
    </DialogContent>
  );
}

function OperatorTeamMetadataForm({
  model,
}: {
  model: React.ComponentProps<typeof OperatorTeamDetailContent>["model"];
}): React.ReactNode {
  const { canManage, detail, isArchiving, isSaving, save, touched } = model;
  if (detail.kind !== "ready") return null;
  return (
    <form className="operator-team-form" onSubmit={save} noValidate>
      <OperatorTeamNameField model={model} />
      <OperatorTeamDescriptionField model={model} />
      {canManage && detail.resource.value.state === "active" ? (
        <Button
          type="submit"
          disabled={
            isSaving || isArchiving || (!touched.name && !touched.description)
          }
        >
          {isSaving ? "Saving changes…" : "Save changes"}
        </Button>
      ) : null}
    </form>
  );
}

function OperatorTeamArchivePanel({
  model,
}: {
  model: React.ComponentProps<typeof OperatorTeamDetailContent>["model"];
}): React.ReactNode {
  const { canManage, detail } = model;
  if (detail.kind !== "ready") return null;
  return canManage && detail.resource.value.state === "active" ? (
    <OperatorTeamArchiveForm model={model} />
  ) : null;
}

function OperatorTeamNameField({
  model,
}: {
  model: React.ComponentProps<typeof OperatorTeamMetadataForm>["model"];
}): React.ReactNode {
  const {
    canManage,
    detail,
    draft,
    fieldErrors,
    id,
    isArchiving,
    isSaving,
    setDraft,
    setFieldErrors,
    setTouched,
  } = model;
  if (detail.kind !== "ready") return null;
  return (
    <FormField
      htmlFor={`${id}-edit-name`}
      label="Team name"
      {...(fieldErrors.name ? { error: fieldErrors.name } : {})}
    >
      <Input
        id={`${id}-edit-name`}
        value={draft.name}
        required
        maxLength={120}
        disabled={
          !canManage ||
          isSaving ||
          isArchiving ||
          detail.resource.value.state === "archived"
        }
        aria-invalid={fieldErrors.name ? "true" : undefined}
        aria-describedby={
          fieldErrors.name ? `${id}-edit-name-error` : undefined
        }
        onChange={(event) => {
          setFieldErrors((current) => withoutTeamFieldError(current, "name"));
          setDraft((current) => ({
            ...current,
            name: event.target.value,
          }));
          setTouched((current) => ({ ...current, name: true }));
        }}
      />
    </FormField>
  );
}

function OperatorTeamDescriptionField({
  model,
}: {
  model: React.ComponentProps<typeof OperatorTeamMetadataForm>["model"];
}): React.ReactNode {
  const {
    canManage,
    detail,
    draft,
    fieldErrors,
    id,
    isArchiving,
    isSaving,
    setDraft,
    setFieldErrors,
    setTouched,
  } = model;
  if (detail.kind !== "ready") return null;
  return (
    <FormField
      htmlFor={`${id}-edit-description`}
      label="Description"
      {...(fieldErrors.description ? { error: fieldErrors.description } : {})}
    >
      <Textarea
        id={`${id}-edit-description`}
        value={draft.description}
        maxLength={500}
        disabled={
          !canManage ||
          isSaving ||
          isArchiving ||
          detail.resource.value.state === "archived"
        }
        aria-invalid={fieldErrors.description ? "true" : undefined}
        aria-describedby={
          fieldErrors.description ? `${id}-edit-description-error` : undefined
        }
        onChange={(event) => {
          setFieldErrors((current) =>
            withoutTeamFieldError(current, "description"),
          );
          setDraft((current) => ({
            ...current,
            description: event.target.value,
          }));
          setTouched((current) => ({
            ...current,
            description: true,
          }));
        }}
      />
    </FormField>
  );
}

function OperatorTeamArchiveForm({
  model,
}: {
  model: React.ComponentProps<typeof OperatorTeamArchivePanel>["model"];
}): React.ReactNode {
  const {
    archive,
    archiveReason,
    archiveReasonError,
    detail,
    id,
    isArchiving,
    isSaving,
    setArchiveReason,
    setArchiveReasonError,
  } = model;
  if (detail.kind !== "ready") return null;
  return (
    <Card className="operator-team-archive-card">
      <CardHeader>
        <CardTitle>Archive global identity</CardTitle>
        <CardDescription>
          Archiving is blocked while any tenant epoch is active. History remains
          addressable.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <FormField
          htmlFor={`${id}-archive-reason`}
          label="Archive reason"
          {...(archiveReasonError ? { error: archiveReasonError } : {})}
        >
          <Textarea
            id={`${id}-archive-reason`}
            value={archiveReason}
            required
            maxLength={500}
            disabled={isSaving || isArchiving}
            aria-invalid={archiveReasonError ? "true" : undefined}
            aria-describedby={
              archiveReasonError ? `${id}-archive-reason-error` : undefined
            }
            onChange={(event) => {
              setArchiveReasonError(null);
              setArchiveReason(event.target.value);
            }}
          />
        </FormField>
        <Button
          type="button"
          variant="destructive"
          disabled={
            isSaving ||
            isArchiving ||
            archiveReason.trim().length === 0 ||
            detail.resource.value.activeAssignmentCount > 0
          }
          onClick={() => void archive()}
        >
          <Archive aria-hidden="true" />
          {isArchiving ? "Archiving team…" : "Archive operator team"}
        </Button>
        {detail.resource.value.activeAssignmentCount > 0 ? (
          <p className="operator-team-inline-note">
            End {detail.resource.value.activeAssignmentCount} active tenant{" "}
            {detail.resource.value.activeAssignmentCount === 1
              ? "epoch"
              : "epochs"}{" "}
            first.
          </p>
        ) : null}
      </CardContent>
    </Card>
  );
}
