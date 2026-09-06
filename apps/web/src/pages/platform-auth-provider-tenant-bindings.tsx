import {
  Alert,
  AlertDescription,
  AlertTitle,
} from "@periapsis/ui/components/ui/alert";
import { Badge } from "@periapsis/ui/components/ui/badge";
import { Button } from "@periapsis/ui/components/ui/button";
import { Input } from "@periapsis/ui/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableRow,
} from "@periapsis/ui/components/ui/table";
import {
  Archive,
  Link2,
  Pencil,
  Plus,
  RefreshCw,
  Save,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import {
  useCallback,
  useEffect,
  useEffectEvent,
  useId,
  useLayoutEffect,
  useMemo,
  useReducer,
  useRef,
} from "react";
import { TableColumnHeaders } from "../components/table-column-headers";
import { FormValidationAlert } from "./form-validation-alert";
import { reduceWorkspaceState } from "./workspace-state";

import { FocusedError } from "../components/focused-error";
import { FormField } from "../components/form-field";
import { idempotencyKeyForPayload } from "../lib/payload-idempotency";
import {
  describePhaseTwoError,
  PhaseTwoApiError,
  type PhaseTwoApi,
  type PlatformAuthProviderTenantBindingView,
  type VersionedView,
} from "../lib/phase-two-types";
import { validatePlatformAuthProviderAuditReason } from "./platform-auth-provider-model";

type BindingListState =
  | { kind: "error"; message: string }
  | { kind: "loading" }
  | {
      items: readonly PlatformAuthProviderTenantBindingView[];
      kind: "ready";
      nextCursor?: string;
    };

type BindingDetailState =
  | { kind: "error"; bindingId: string; message: string }
  | { kind: "idle" }
  | { kind: "loading"; bindingId: string }
  | {
      kind: "ready";
      value: VersionedView<PlatformAuthProviderTenantBindingView>;
    };

interface BindingDraft {
  auditReason: string;
  loginKey: string;
  profilePriority: string;
}

interface CreateBindingDraft extends BindingDraft {
  tenantId: string;
}

type BindingJitMode = "create" | "disabled";
type BindingLifecycleCommand = "activate" | "deactivate";
type BindingNoMatchPolicy = "deny" | "provider_access_only";

interface PlatformAuthProviderTenantBindingsProps {
  api: PhaseTwoApi;
  canManage: boolean;
  canRead: boolean;
  csrfToken: string;
  onMutationBusyChange: (busy: boolean) => void;
  onNotice: (notice: { message: string; tone: "success" | "warning" }) => void;
  onPermissionError: () => void;
  onProviderProjectionStale?: () => void;
  onUnauthenticated: () => void;
  providerArchived: boolean;
  providerAccountMode?: "create" | "disabled" | "existing_identity";
  providerEnabled?: boolean;
  providerKind?: "oidc" | "saml";
  providerMutationBusy: boolean;
  providerId: string;
  refreshRevision?: number;
  sessionId: string;
}

const emptyCreateDraft: CreateBindingDraft = {
  auditReason: "",
  loginKey: "",
  profilePriority: "100",
  tenantId: "",
};

export function PlatformAuthProviderTenantBindings(
  props: PlatformAuthProviderTenantBindingsProps,
): React.JSX.Element {
  const model = usePlatformAuthProviderTenantBindingsModel(props);
  if (model.kind === "content") return model.content;
  return <PlatformAuthProviderTenantBindingsView model={model.data} />;
}

function usePlatformAuthProviderTenantBindingsModel({
  api,
  canManage,
  canRead,
  csrfToken,
  onMutationBusyChange,
  onNotice,
  onPermissionError,
  onProviderProjectionStale,
  onUnauthenticated,
  providerArchived,
  providerAccountMode,
  providerEnabled,
  providerKind,
  providerMutationBusy,
  providerId,
  refreshRevision = 0,
  sessionId,
}: PlatformAuthProviderTenantBindingsProps) {
  const titleId = useId();
  const handleAuthorizationError = useCallback(
    (caught: unknown): boolean => {
      if (caught instanceof PhaseTwoApiError && caught.status === 401) {
        onUnauthenticated();
        return true;
      }
      if (caught instanceof PhaseTwoApiError && caught.status === 403) {
        onPermissionError();
      }
      return false;
    },
    [onUnauthenticated, onPermissionError],
  );
  const [workspaceState, updateWorkspaceState] = useReducer(
    reduceWorkspaceState<PlatformAuthProviderTenantBindingsState>,
    undefined,
    (): PlatformAuthProviderTenantBindingsState => ({
      listState: {
        kind: "loading",
      },
      listRevision: 0,
      paginationError: null,
      loadingMore: false,
      createOpen: false,
      createDraft: emptyCreateDraft,
      detailState: {
        kind: "idle",
      },
      editDraft: null,
      archiveOpen: false,
      archiveReason: "",
      archiveConfirmation: "",
      lifecycleCommand: null,
      lifecycleReason: "",
      lifecycleConfirmation: "",
      jitMode: "disabled",
      noMatchPolicy: "deny",
      validationErrors: [],
      mutationError: null,
      submitting: null,
      providerActiveObserved: false,
    }),
  );
  const {
    listState,
    listRevision,
    paginationError,
    loadingMore,
    createOpen,
    createDraft,
    detailState,
    editDraft,
    archiveOpen,
    archiveReason,
    archiveConfirmation,
    lifecycleCommand,
    lifecycleReason,
    lifecycleConfirmation,
    jitMode,
    noMatchPolicy,
    validationErrors,
    mutationError,
    submitting,
    providerActiveObserved,
  } = workspaceState;
  const {
    setListState,
    setListRevision,
    setPaginationError,
    setLoadingMore,
    setCreateOpen,
    setCreateDraft,
    setDetailState,
    setEditDraft,
    setArchiveOpen,
    setArchiveReason,
    setArchiveConfirmation,
    setLifecycleCommand,
    setLifecycleReason,
    setLifecycleConfirmation,
    setJitMode,
    setNoMatchPolicy,
    setValidationErrors,
    setMutationError,
    setSubmitting,
    setProviderActiveObserved,
  } = useMemo(
    () => ({
      setListState: (
        value: React.SetStateAction<
          PlatformAuthProviderTenantBindingsState["listState"]
        >,
      ) => updateWorkspaceState({ listState: value }),
      setListRevision: (
        value: React.SetStateAction<
          PlatformAuthProviderTenantBindingsState["listRevision"]
        >,
      ) => updateWorkspaceState({ listRevision: value }),
      setPaginationError: (
        value: React.SetStateAction<
          PlatformAuthProviderTenantBindingsState["paginationError"]
        >,
      ) => updateWorkspaceState({ paginationError: value }),
      setLoadingMore: (
        value: React.SetStateAction<
          PlatformAuthProviderTenantBindingsState["loadingMore"]
        >,
      ) => updateWorkspaceState({ loadingMore: value }),
      setCreateOpen: (
        value: React.SetStateAction<
          PlatformAuthProviderTenantBindingsState["createOpen"]
        >,
      ) => updateWorkspaceState({ createOpen: value }),
      setCreateDraft: (
        value: React.SetStateAction<
          PlatformAuthProviderTenantBindingsState["createDraft"]
        >,
      ) => updateWorkspaceState({ createDraft: value }),
      setDetailState: (
        value: React.SetStateAction<
          PlatformAuthProviderTenantBindingsState["detailState"]
        >,
      ) => updateWorkspaceState({ detailState: value }),
      setEditDraft: (
        value: React.SetStateAction<
          PlatformAuthProviderTenantBindingsState["editDraft"]
        >,
      ) => updateWorkspaceState({ editDraft: value }),
      setArchiveOpen: (
        value: React.SetStateAction<
          PlatformAuthProviderTenantBindingsState["archiveOpen"]
        >,
      ) => updateWorkspaceState({ archiveOpen: value }),
      setArchiveReason: (
        value: React.SetStateAction<
          PlatformAuthProviderTenantBindingsState["archiveReason"]
        >,
      ) => updateWorkspaceState({ archiveReason: value }),
      setArchiveConfirmation: (
        value: React.SetStateAction<
          PlatformAuthProviderTenantBindingsState["archiveConfirmation"]
        >,
      ) => updateWorkspaceState({ archiveConfirmation: value }),
      setLifecycleCommand: (
        value: React.SetStateAction<
          PlatformAuthProviderTenantBindingsState["lifecycleCommand"]
        >,
      ) => updateWorkspaceState({ lifecycleCommand: value }),
      setLifecycleReason: (
        value: React.SetStateAction<
          PlatformAuthProviderTenantBindingsState["lifecycleReason"]
        >,
      ) => updateWorkspaceState({ lifecycleReason: value }),
      setLifecycleConfirmation: (
        value: React.SetStateAction<
          PlatformAuthProviderTenantBindingsState["lifecycleConfirmation"]
        >,
      ) => updateWorkspaceState({ lifecycleConfirmation: value }),
      setJitMode: (
        value: React.SetStateAction<
          PlatformAuthProviderTenantBindingsState["jitMode"]
        >,
      ) => updateWorkspaceState({ jitMode: value }),
      setNoMatchPolicy: (
        value: React.SetStateAction<
          PlatformAuthProviderTenantBindingsState["noMatchPolicy"]
        >,
      ) => updateWorkspaceState({ noMatchPolicy: value }),
      setValidationErrors: (
        value: React.SetStateAction<
          PlatformAuthProviderTenantBindingsState["validationErrors"]
        >,
      ) => updateWorkspaceState({ validationErrors: value }),
      setMutationError: (
        value: React.SetStateAction<
          PlatformAuthProviderTenantBindingsState["mutationError"]
        >,
      ) => updateWorkspaceState({ mutationError: value }),
      setSubmitting: (
        value: React.SetStateAction<
          PlatformAuthProviderTenantBindingsState["submitting"]
        >,
      ) => updateWorkspaceState({ submitting: value }),
      setProviderActiveObserved: (
        value: React.SetStateAction<
          PlatformAuthProviderTenantBindingsState["providerActiveObserved"]
        >,
      ) => updateWorkspaceState({ providerActiveObserved: value }),
    }),
    [updateWorkspaceState],
  );

  const providerExecutionActive =
    providerEnabled === true || providerActiveObserved;
  const contextRef = useRef({
    canManage,
    canRead,
    providerArchived,
    providerExecutionActive,
    providerMutationBusy,
    providerId,
    sessionId,
  });
  const mountedRef = useRef(false);
  const listEpochRef = useRef(0);
  const detailEpochRef = useRef(0);
  const detailAbortRef = useRef<AbortController | null>(null);
  const externalRefreshRef = useRef(refreshRevision);
  const paginationAbortRef = useRef<AbortController | null>(null);
  const paginationLockRef = useRef(false);
  const mutationLockRef = useRef<symbol | null>(null);
  const cursorHistoryRef = useRef(new Set<string>());
  const idempotencyBindingRef = useRef<{
    fingerprint: string;
    key: string;
  } | null>(null);
  useLayoutEffect(() => {
    contextRef.current = {
      canManage,
      canRead,
      providerArchived,
      providerExecutionActive,
      providerMutationBusy,
      providerId,
      sessionId,
    };
  }, [
    canManage,
    canRead,
    providerArchived,
    providerExecutionActive,
    providerId,
    providerMutationBusy,
    sessionId,
  ]);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      detailAbortRef.current?.abort();
      paginationAbortRef.current?.abort();
      listEpochRef.current += 1;
      detailEpochRef.current += 1;
      mutationLockRef.current = null;
      onMutationBusyChange(false);
    };
  }, [onMutationBusyChange]);

  useEffect(() => {
    updateWorkspaceState({
      createOpen: false,
      createDraft: emptyCreateDraft,
      detailState: { kind: "idle" },
      editDraft: null,
      archiveOpen: false,
      archiveReason: "",
      archiveConfirmation: "",
      lifecycleCommand: null,
      lifecycleReason: "",
      lifecycleConfirmation: "",
      jitMode: "disabled",
      noMatchPolicy: "deny",
      validationErrors: [],
      mutationError: null,
      submitting: null,
      providerActiveObserved: false,
      paginationError: null,
    });
    detailAbortRef.current?.abort();
    detailAbortRef.current = null;
    paginationAbortRef.current?.abort();
    paginationAbortRef.current = null;
    listEpochRef.current += 1;
    detailEpochRef.current += 1;
    paginationLockRef.current = false;
    mutationLockRef.current = null;
    onMutationBusyChange(false);
    cursorHistoryRef.current.clear();
    idempotencyBindingRef.current = null;
  }, [onMutationBusyChange, providerId, sessionId]);

  useEffect(() => {
    if (providerEnabled === false) setProviderActiveObserved(false);
  }, [setProviderActiveObserved, providerEnabled]);

  useEffect(() => {
    if (canRead) return;
    detailAbortRef.current?.abort();
    detailAbortRef.current = null;
    paginationAbortRef.current?.abort();
    paginationAbortRef.current = null;
    listEpochRef.current += 1;
    detailEpochRef.current += 1;
    paginationLockRef.current = false;
    mutationLockRef.current = null;
    onMutationBusyChange(false);
    updateWorkspaceState({
      createOpen: false,
      createDraft: emptyCreateDraft,
      listState: { kind: "loading" },
      detailState: { kind: "idle" },
      editDraft: null,
      archiveOpen: false,
      archiveReason: "",
      archiveConfirmation: "",
      lifecycleCommand: null,
      lifecycleReason: "",
      lifecycleConfirmation: "",
      mutationError: null,
      validationErrors: [],
      submitting: null,
      paginationError: null,
      loadingMore: false,
    });
    idempotencyBindingRef.current = null;
  }, [canRead, onMutationBusyChange]);

  useEffect(() => {
    if (canManage && !providerArchived && !providerMutationBusy) return;
    const mutationWasPending = mutationLockRef.current !== null;
    mutationLockRef.current = null;
    setSubmitting(null);
    if (mutationWasPending) onMutationBusyChange(false);
    updateWorkspaceState({
      createOpen: false,
      createDraft: emptyCreateDraft,
      editDraft: null,
      archiveOpen: false,
      archiveReason: "",
      archiveConfirmation: "",
      lifecycleCommand: null,
      lifecycleReason: "",
      lifecycleConfirmation: "",
      jitMode: "disabled",
      noMatchPolicy: "deny",
      validationErrors: [],
      mutationError: null,
    });
    idempotencyBindingRef.current = null;
  }, [
    setSubmitting,
    canManage,
    onMutationBusyChange,
    providerArchived,
    providerMutationBusy,
  ]);

  useEffect(() => {
    if (!providerExecutionActive) return;
    updateWorkspaceState({ createOpen: false, createDraft: emptyCreateDraft });
    idempotencyBindingRef.current = null;
    if (submitting === "create") {
      mutationLockRef.current = null;
      setSubmitting(null);
      onMutationBusyChange(false);
    }
  }, [
    setSubmitting,
    onMutationBusyChange,
    providerExecutionActive,
    submitting,
  ]);

  const refreshSelectedBinding = useEffectEvent((bindingId: string) => {
    void inspectBinding(bindingId);
  });

  useEffect(() => {
    if (externalRefreshRef.current === refreshRevision) return;
    externalRefreshRef.current = refreshRevision;
    const bindingId =
      detailState.kind === "ready"
        ? detailState.value.value.id
        : detailState.kind === "loading" || detailState.kind === "error"
          ? detailState.bindingId
          : null;
    if (bindingId !== null && canRead) refreshSelectedBinding(bindingId);
  }, [canRead, detailState, refreshRevision]);

  useEffect(() => {
    if (!canRead) return undefined;
    paginationAbortRef.current?.abort();
    paginationAbortRef.current = null;
    const controller = new AbortController();
    const expectedProviderId = providerId;
    const expectedSessionId = sessionId;
    const listEpoch = listEpochRef.current + 1;
    listEpochRef.current = listEpoch;
    paginationLockRef.current = true;
    cursorHistoryRef.current.clear();
    updateWorkspaceState({
      listState: { kind: "loading" },
      loadingMore: true,
      paginationError: null,
    });
    void api
      .listPlatformAuthProviderTenantBindings(providerId, {
        includeArchived: true,
        signal: controller.signal,
      })
      .then((page) => {
        if (
          controller.signal.aborted ||
          listEpochRef.current !== listEpoch ||
          !readContextIsCurrent(expectedProviderId, expectedSessionId)
        ) {
          return;
        }
        if (page.nextCursor) cursorHistoryRef.current.add(page.nextCursor);
        if (page.items.some(bindingRequiresActiveProvider)) {
          setProviderActiveObserved(true);
        }
        setListState({
          items: page.items,
          kind: "ready",
          ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
        });
      })
      .catch((caught: unknown) => {
        if (
          controller.signal.aborted ||
          listEpochRef.current !== listEpoch ||
          isAbortError(caught) ||
          !readContextIsCurrent(expectedProviderId, expectedSessionId) ||
          handleAuthorizationError(caught)
        ) {
          return;
        }
        setListState({
          kind: "error",
          message: describePhaseTwoError(
            caught,
            "Tenant bindings could not be loaded.",
          ),
        });
      })
      .finally(() => {
        if (
          listEpochRef.current === listEpoch &&
          readContextIsCurrent(expectedProviderId, expectedSessionId)
        ) {
          paginationLockRef.current = false;
          setLoadingMore(false);
        }
      });
    return () => {
      controller.abort();
      if (listEpochRef.current === listEpoch) listEpochRef.current += 1;
    };
  }, [
    setProviderActiveObserved,
    setListState,
    setLoadingMore,
    api,
    canRead,
    handleAuthorizationError,
    listRevision,
    providerId,
    refreshRevision,
    sessionId,
  ]);

  function contextIsCurrent(
    expectedProviderId: string,
    expectedSessionId: string,
  ): boolean {
    return (
      mountedRef.current &&
      contextRef.current.providerId === expectedProviderId &&
      contextRef.current.sessionId === expectedSessionId
    );
  }

  function readContextIsCurrent(
    expectedProviderId: string,
    expectedSessionId: string,
  ): boolean {
    return (
      contextRef.current.canRead &&
      contextIsCurrent(expectedProviderId, expectedSessionId)
    );
  }

  function mutationIsCurrent(
    token: symbol,
    expectedProviderId: string,
    expectedSessionId: string,
  ): boolean {
    return (
      mutationLockRef.current === token &&
      contextRef.current.canManage &&
      contextRef.current.canRead &&
      !contextRef.current.providerArchived &&
      !contextRef.current.providerMutationBusy &&
      contextIsCurrent(expectedProviderId, expectedSessionId)
    );
  }

  function releaseMutation(
    token: symbol,
    expectedProviderId: string,
    expectedSessionId: string,
  ): void {
    if (mutationLockRef.current !== token) return;
    mutationLockRef.current = null;
    onMutationBusyChange(false);
    if (contextIsCurrent(expectedProviderId, expectedSessionId)) {
      setSubmitting(null);
    }
  }

  async function loadMore(): Promise<void> {
    if (
      listState.kind !== "ready" ||
      !listState.nextCursor ||
      paginationLockRef.current
    ) {
      return;
    }
    const cursor = listState.nextCursor;
    const expectedProviderId = providerId;
    const expectedSessionId = sessionId;
    const listEpoch = listEpochRef.current;
    const controller = new AbortController();
    paginationAbortRef.current?.abort();
    paginationAbortRef.current = controller;
    paginationLockRef.current = true;
    updateWorkspaceState({ loadingMore: true, paginationError: null });
    try {
      const page = await api.listPlatformAuthProviderTenantBindings(
        providerId,
        {
          after: cursor,
          includeArchived: true,
          signal: controller.signal,
        },
      );
      if (
        controller.signal.aborted ||
        listEpochRef.current !== listEpoch ||
        !readContextIsCurrent(expectedProviderId, expectedSessionId)
      ) {
        return;
      }
      if (
        page.nextCursor !== undefined &&
        (page.nextCursor <= cursor ||
          cursorHistoryRef.current.has(page.nextCursor))
      ) {
        throw new Error("The tenant-binding cursor did not advance.");
      }
      const ids = new Set(listState.items.map((binding) => binding.id));
      const tenants = new Set(
        listState.items.map((binding) => binding.tenant.id),
      );
      if (
        page.items.some(
          (binding) =>
            binding.id <= cursor ||
            ids.has(binding.id) ||
            tenants.has(binding.tenant.id),
        )
      ) {
        throw new Error(
          "The tenant-binding page did not preserve keyset progression.",
        );
      }
      if (page.nextCursor) cursorHistoryRef.current.add(page.nextCursor);
      if (page.items.some(bindingRequiresActiveProvider)) {
        setProviderActiveObserved(true);
      }
      setListState((current) =>
        current.kind === "ready" && current.nextCursor === cursor
          ? {
              items: [...current.items, ...page.items],
              kind: "ready",
              ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
            }
          : current,
      );
    } catch (caught) {
      if (
        controller.signal.aborted ||
        isAbortError(caught) ||
        listEpochRef.current !== listEpoch ||
        !readContextIsCurrent(expectedProviderId, expectedSessionId) ||
        handleAuthorizationError(caught)
      ) {
        return;
      }
      setPaginationError(
        describePhaseTwoError(
          caught,
          "More tenant bindings could not be loaded.",
        ),
      );
    } finally {
      if (
        paginationAbortRef.current === controller &&
        listEpochRef.current === listEpoch &&
        readContextIsCurrent(expectedProviderId, expectedSessionId)
      ) {
        paginationAbortRef.current = null;
        paginationLockRef.current = false;
        // react-doctor-disable-next-line no-loading-flag-reset-outside-finally -- The owning request clears this flag in finally; the generation guard protects newer requests.
        setLoadingMore(false);
      }
    }
  }

  async function inspectBinding(
    bindingId: string,
    duringConflictRefresh = false,
  ): Promise<void> {
    if (
      !canRead ||
      (!duringConflictRefresh && mutationLockRef.current !== null)
    ) {
      return;
    }
    const expectedProviderId = providerId;
    const expectedSessionId = sessionId;
    const detailEpoch = detailEpochRef.current + 1;
    const controller = new AbortController();
    detailAbortRef.current?.abort();
    detailAbortRef.current = controller;
    detailEpochRef.current = detailEpoch;
    updateWorkspaceState({
      createOpen: false,
      detailState: { bindingId, kind: "loading" },
      editDraft: null,
      archiveOpen: false,
      archiveReason: "",
      archiveConfirmation: "",
      lifecycleCommand: null,
      lifecycleReason: "",
      lifecycleConfirmation: "",
      validationErrors: [],
      mutationError: null,
    });
    try {
      const detail = await api.getPlatformAuthProviderTenantBinding(
        providerId,
        bindingId,
        controller.signal,
      );
      if (
        controller.signal.aborted ||
        detailEpochRef.current !== detailEpoch ||
        !readContextIsCurrent(expectedProviderId, expectedSessionId)
      ) {
        return;
      }
      setDetailState({ kind: "ready", value: detail });
      if (bindingRequiresActiveProvider(detail.value)) {
        setProviderActiveObserved(true);
      }
    } catch (caught) {
      if (
        controller.signal.aborted ||
        isAbortError(caught) ||
        detailEpochRef.current !== detailEpoch ||
        !readContextIsCurrent(expectedProviderId, expectedSessionId) ||
        handleAuthorizationError(caught)
      ) {
        return;
      }
      setDetailState({
        bindingId,
        kind: "error",
        message: describePhaseTwoError(
          caught,
          "The tenant-binding detail could not be loaded.",
        ),
      });
    } finally {
      if (detailAbortRef.current === controller) {
        detailAbortRef.current = null;
      }
    }
  }

  function refreshBindingAfterConflict(
    bindingId: string,
    message: string,
  ): void {
    onNotice({ message, tone: "warning" });
    onProviderProjectionStale?.();
    setListRevision((revision) => revision + 1);
    void inspectBinding(bindingId, true);
  }

  async function createBinding(
    event: React.FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault();
    if (
      !canManage ||
      providerArchived ||
      providerExecutionActive ||
      providerMutationBusy ||
      mutationLockRef.current !== null
    ) {
      return;
    }
    const errors = validateCreateDraft(createDraft);
    updateWorkspaceState({ validationErrors: errors, mutationError: null });
    if (errors.length > 0) return;
    const input = {
      loginKey: createDraft.loginKey,
      profilePriority: Number(createDraft.profilePriority),
      tenantId: createDraft.tenantId,
    };
    const idempotencyKey = idempotencyKeyForPayload(idempotencyBindingRef, {
      auditReason: createDraft.auditReason,
      input,
      providerId,
    });
    const expectedProviderId = providerId;
    const expectedSessionId = sessionId;
    const mutationToken = Symbol("platform-provider-tenant-binding-create");
    mutationLockRef.current = mutationToken;
    onMutationBusyChange(true);
    setSubmitting("create");
    try {
      const created = await api.createPlatformAuthProviderTenantBinding(
        csrfToken,
        providerId,
        idempotencyKey,
        createDraft.auditReason,
        input,
      );
      if (
        !mutationIsCurrent(
          mutationToken,
          expectedProviderId,
          expectedSessionId,
        ) ||
        contextRef.current.providerExecutionActive
      ) {
        return;
      }
      idempotencyBindingRef.current = null;
      updateWorkspaceState({
        createDraft: emptyCreateDraft,
        createOpen: false,
        detailState: { kind: "ready", value: created },
        listRevision: (revision) => revision + 1,
      });
      if (created.value.archivedAt !== null) {
        onNotice({
          message: `${created.value.tenant.name} binding is already archived. The safe retry returned its current state and did not create or reactivate a binding.`,
          tone: "warning",
        });
      } else if (bindingRequiresActiveProvider(created.value)) {
        setProviderActiveObserved(true);
        onProviderProjectionStale?.();
        onNotice({
          message: created.value.enabled
            ? `${created.value.tenant.name} binding is already active. The safe retry returned its current state and did not create a new access epoch.`
            : `${created.value.tenant.name} binding is already ready to activate. The safe retry returned its current state and did not create or activate a binding.`,
          tone: "warning",
        });
      } else if (created.value.version > 1) {
        onNotice({
          message: `${created.value.tenant.name} binding already exists and is currently disabled. The safe retry returned its later version without creating or activating a binding.`,
          tone: "warning",
        });
      } else {
        onNotice({
          message: `${created.value.tenant.name} was explicitly bound disabled. It can be activated only after server readiness is returned.`,
          tone: "success",
        });
      }
    } catch (caught) {
      if (
        !mutationIsCurrent(
          mutationToken,
          expectedProviderId,
          expectedSessionId,
        ) ||
        contextRef.current.providerExecutionActive ||
        handleAuthorizationError(caught)
      ) {
        return;
      }
      if (caught instanceof PhaseTwoApiError && caught.status === 409) {
        onProviderProjectionStale?.();
        idempotencyBindingRef.current = null;
        updateWorkspaceState({
          createDraft: emptyCreateDraft,
          createOpen: false,
          validationErrors: [],
          mutationError: null,
          listRevision: (revision) => revision + 1,
        });
        onNotice({
          message:
            "The create request conflicted with current state. Exact replay is bounded to 24 hours; the authorized tenant-binding list is being reloaded before a new attempt.",
          tone: "warning",
        });
        return;
      }
      setMutationError(
        describePhaseTwoError(
          caught,
          "The tenant binding was not created. An unchanged request can be retried safely.",
        ),
      );
    } finally {
      releaseMutation(mutationToken, expectedProviderId, expectedSessionId);
    }
  }

  async function updateBinding(
    event: React.FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault();
    if (
      !canManage ||
      providerArchived ||
      providerMutationBusy ||
      mutationLockRef.current !== null ||
      detailState.kind !== "ready" ||
      detailState.value.value.enabled ||
      !editDraft
    ) {
      return;
    }
    const errors = validateBindingDraft(editDraft);
    updateWorkspaceState({ validationErrors: errors, mutationError: null });
    if (errors.length > 0) return;
    const current = detailState.value;
    const expectedProviderId = providerId;
    const expectedSessionId = sessionId;
    const mutationToken = Symbol("platform-provider-tenant-binding-update");
    mutationLockRef.current = mutationToken;
    onMutationBusyChange(true);
    setSubmitting("update");
    try {
      const updated = await api.updatePlatformAuthProviderTenantBinding(
        csrfToken,
        providerId,
        current.value.id,
        current,
        editDraft.auditReason,
        {
          expectedTenantVersion: current.value.tenant.version,
          expectedVersion: current.value.version,
          loginKey: editDraft.loginKey,
          profilePriority: Number(editDraft.profilePriority),
        },
      );
      if (
        !mutationIsCurrent(mutationToken, expectedProviderId, expectedSessionId)
      ) {
        return;
      }
      setDetailState({ kind: "ready", value: updated });
      if (bindingRequiresActiveProvider(updated.value)) {
        setProviderActiveObserved(true);
      }
      updateWorkspaceState({
        editDraft: null,
        validationErrors: [],
        listRevision: (revision) => revision + 1,
      });
      onNotice({
        message: `${updated.value.tenant.name} binding metadata was updated without changing its admission lifecycle.`,
        tone: "success",
      });
    } catch (caught) {
      if (
        !mutationIsCurrent(
          mutationToken,
          expectedProviderId,
          expectedSessionId,
        ) ||
        handleAuthorizationError(caught)
      ) {
        return;
      }
      if (
        caught instanceof PhaseTwoApiError &&
        (caught.status === 409 || caught.status === 412)
      ) {
        refreshBindingAfterConflict(
          current.value.id,
          caught.status === 412
            ? "The tenant binding changed on the server. Its current detail and authorized inventory are being reloaded; start the edit again."
            : "The tenant-binding update conflicted with current state. Its exact detail and authorized inventory are being reloaded before another attempt.",
        );
        return;
      }
      setMutationError(
        describePhaseTwoError(
          caught,
          "The tenant binding was not updated. Reload its current version before retrying.",
        ),
      );
    } finally {
      releaseMutation(mutationToken, expectedProviderId, expectedSessionId);
    }
  }

  async function changeBindingAccess(
    event: React.FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault();
    if (
      !canManage ||
      providerArchived ||
      providerMutationBusy ||
      mutationLockRef.current !== null ||
      detailState.kind !== "ready" ||
      lifecycleCommand === null ||
      providerKind === "saml" ||
      providerEnabled === false ||
      (lifecycleCommand === "activate" &&
        jitMode === "create" &&
        providerAccountMode !== undefined &&
        providerAccountMode !== "create") ||
      detailState.value.value.archivedAt !== null ||
      (lifecycleCommand === "activate" &&
        (detailState.value.value.enabled ||
          !detailState.value.value.activationAvailable)) ||
      (lifecycleCommand === "deactivate" && !detailState.value.value.enabled)
    ) {
      return;
    }
    const current = detailState.value;
    const reasonError =
      validatePlatformAuthProviderAuditReason(lifecycleReason);
    const errors = [
      ...(reasonError ? [reasonError] : []),
      ...(lifecycleConfirmation === current.value.loginKey
        ? []
        : [`Type ${current.value.loginKey} to confirm ${lifecycleCommand}.`]),
    ];
    updateWorkspaceState({ validationErrors: errors, mutationError: null });
    if (errors.length > 0) return;
    const expectedProviderId = providerId;
    const expectedSessionId = sessionId;
    const command = lifecycleCommand;
    const mutationToken = Symbol(`platform-provider-tenant-binding-${command}`);
    mutationLockRef.current = mutationToken;
    onMutationBusyChange(true);
    setSubmitting(command);
    try {
      const updated =
        command === "activate"
          ? await api.activatePlatformAuthProviderTenantBinding(
              csrfToken,
              providerId,
              current.value.id,
              current,
              lifecycleReason,
              {
                expectedTenantVersion: current.value.tenant.version,
                expectedVersion: current.value.version,
                jitMode,
                noMatchPolicy,
              },
            )
          : await api.deactivatePlatformAuthProviderTenantBinding(
              csrfToken,
              providerId,
              current.value.id,
              current,
              lifecycleReason,
              {
                expectedTenantVersion: current.value.tenant.version,
                expectedVersion: current.value.version,
              },
            );
      if (
        !mutationIsCurrent(mutationToken, expectedProviderId, expectedSessionId)
      ) {
        return;
      }
      setDetailState({ kind: "ready", value: updated });
      if (bindingRequiresActiveProvider(updated.value)) {
        setProviderActiveObserved(true);
      }
      updateWorkspaceState({
        lifecycleCommand: null,
        lifecycleReason: "",
        lifecycleConfirmation: "",
        validationErrors: [],
        listRevision: (revision) => revision + 1,
      });
      onNotice({
        message:
          command === "activate"
            ? `${updated.value.tenant.name} tenant admission is active with ${humanizeBindingPolicy(updated.value.jitMode)} and ${humanizeBindingPolicy(updated.value.noMatchPolicy)}. No platform role is created.`
            : `${updated.value.tenant.name} tenant admission was deactivated and its live access epoch was closed.`,
        tone: "success",
      });
    } catch (caught) {
      if (
        !mutationIsCurrent(
          mutationToken,
          expectedProviderId,
          expectedSessionId,
        ) ||
        handleAuthorizationError(caught)
      ) {
        return;
      }
      if (
        caught instanceof PhaseTwoApiError &&
        (caught.status === 409 || caught.status === 412)
      ) {
        updateWorkspaceState({
          lifecycleCommand: null,
          lifecycleReason: "",
          lifecycleConfirmation: "",
        });
        refreshBindingAfterConflict(
          current.value.id,
          caught.status === 412
            ? "The tenant binding changed on the server. Its current detail and strong ETag are being reloaded before another lifecycle attempt."
            : "The tenant-binding lifecycle command conflicted with current readiness. Its exact detail and authorized inventory are being reloaded.",
        );
        return;
      }
      setMutationError(
        describePhaseTwoError(
          caught,
          `The tenant binding was not ${command}d. Reload its current version and readiness before retrying.`,
        ),
      );
    } finally {
      releaseMutation(mutationToken, expectedProviderId, expectedSessionId);
    }
  }

  async function archiveBinding(
    event: React.FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault();
    if (
      !canManage ||
      providerArchived ||
      providerMutationBusy ||
      mutationLockRef.current !== null ||
      detailState.kind !== "ready" ||
      detailState.value.value.archivedAt !== null ||
      detailState.value.value.enabled
    ) {
      return;
    }
    const current = detailState.value;
    const reasonError = validatePlatformAuthProviderAuditReason(archiveReason);
    const errors = [
      ...(reasonError ? [reasonError] : []),
      ...(archiveConfirmation === current.value.loginKey
        ? []
        : [`Type ${current.value.loginKey} to confirm archival.`]),
    ];
    updateWorkspaceState({ validationErrors: errors, mutationError: null });
    if (errors.length > 0) return;
    const expectedProviderId = providerId;
    const expectedSessionId = sessionId;
    const mutationToken = Symbol("platform-provider-tenant-binding-archive");
    mutationLockRef.current = mutationToken;
    onMutationBusyChange(true);
    setSubmitting("archive");
    try {
      await api.archivePlatformAuthProviderTenantBinding(
        csrfToken,
        providerId,
        current.value.id,
        current.etag,
        archiveReason,
        {
          expectedTenantVersion: current.value.tenant.version,
          expectedVersion: current.value.version,
        },
      );
      if (
        !mutationIsCurrent(mutationToken, expectedProviderId, expectedSessionId)
      ) {
        return;
      }
      updateWorkspaceState({
        detailState: { kind: "idle" },
        archiveOpen: false,
        archiveReason: "",
        archiveConfirmation: "",
        listRevision: (revision) => revision + 1,
      });
      onNotice({
        message: `${current.value.tenant.name} binding was archived after its admission lifecycle was disabled.`,
        tone: "success",
      });
    } catch (caught) {
      if (
        !mutationIsCurrent(
          mutationToken,
          expectedProviderId,
          expectedSessionId,
        ) ||
        handleAuthorizationError(caught)
      ) {
        return;
      }
      if (
        caught instanceof PhaseTwoApiError &&
        (caught.status === 409 || caught.status === 412)
      ) {
        refreshBindingAfterConflict(
          current.value.id,
          caught.status === 412
            ? "The tenant binding changed on the server. Its current detail and authorized inventory are being reloaded before another archival attempt."
            : "The tenant-binding archival conflicted with current state. Its exact detail and authorized inventory are being reloaded before another attempt.",
        );
        return;
      }
      setMutationError(
        describePhaseTwoError(
          caught,
          "The tenant binding was not archived. Reload its current version before retrying.",
        ),
      );
    } finally {
      releaseMutation(mutationToken, expectedProviderId, expectedSessionId);
    }
  }

  if (!canRead) {
    return {
      kind: "content" as const,
      content: (
        <section className="platform-idp-bindings" aria-labelledby={titleId}>
          <div className="platform-idp-section-heading">
            <div>
              <p className="section-label">Cross-boundary admission</p>
              <h3 id={titleId}>Tenant bindings</h3>
            </div>
          </div>
          <Alert>
            <ShieldCheck aria-hidden="true" />
            <AlertTitle>Binding read permission not returned</AlertTitle>
            <AlertDescription>
              Provider read authority does not reveal tenant bindings. The API
              remains the authorization boundary.
            </AlertDescription>
          </Alert>
        </section>
      ),
    };
  }

  const canMutate = canManage && !providerArchived && !providerMutationBusy;
  const canCreate = canMutate && !providerExecutionActive;
  const selected = detailState.kind === "ready" ? detailState.value : null;

  return {
    kind: "ready" as const,
    data: {
      String,
      archiveBinding,
      archiveConfirmation,
      archiveOpen,
      archiveReason,
      canCreate,
      canMutate,
      changeBindingAccess,
      createBinding,
      createDraft,
      createOpen,
      detailAbortRef,
      detailEpochRef,
      detailState,
      editDraft,
      idempotencyBindingRef,
      inspectBinding,
      jitMode,
      lifecycleCommand,
      lifecycleConfirmation,
      lifecycleReason,
      listState,
      loadMore,
      loadingMore,
      mutationError,
      noMatchPolicy,
      paginationError,
      providerAccountMode,
      providerArchived,
      providerEnabled,
      providerExecutionActive,
      providerKind,
      providerMutationBusy,
      selected,
      setArchiveConfirmation,
      setArchiveOpen,
      setArchiveReason,
      setCreateDraft,
      setCreateOpen,
      setDetailState,
      setEditDraft,
      setJitMode,
      setLifecycleCommand,
      setLifecycleConfirmation,
      setLifecycleReason,
      setListRevision,
      setMutationError,
      setNoMatchPolicy,
      setValidationErrors,
      submitting,
      titleId,
      updateBinding,
      validationErrors,
    },
  };
}

function PlatformAuthProviderTenantBindingsView({
  model,
}: {
  model: Extract<
    ReturnType<typeof usePlatformAuthProviderTenantBindingsModel>,
    { kind: "ready" }
  >["data"];
}): React.JSX.Element {
  const { detailState, listState, paginationError, selected, titleId } = model;
  return (
    <section className="platform-idp-bindings" aria-labelledby={titleId}>
      <BindingInventoryHeading model={model} />

      <Alert className="platform-idp-binding-gate">
        <ShieldAlert aria-hidden="true" />
        <AlertTitle>Explicit tenant admission boundary</AlertTitle>
        <AlertDescription>
          Ready bindings can be activated with an explicit JIT and no-match
          policy. Activation never creates platform roles or enables direct
          platform login.
        </AlertDescription>
      </Alert>

      {<BindingCreatePanel model={model} />}

      {listState.kind === "loading" ? (
        <p role="status">Loading tenant bindings…</p>
      ) : null}
      {<BindingInventoryError model={model} />}
      {<BindingInventoryTable model={model} />}
      {paginationError ? <FocusedError message={paginationError} /> : null}
      {<BindingInventoryPagination model={model} />}

      {detailState.kind === "loading" ? (
        <p role="status">Loading tenant-binding detail…</p>
      ) : null}
      {<BindingDetailError model={model} />}
      {selected ? (
        <div className="platform-idp-binding-detail">
          <BindingDetailHeading model={model} />
          <BindingFacts model={model} />
          {<BindingActionsPanel model={model} />}

          {<BindingMetadataPanel model={model} />}

          {<BindingLifecyclePanel model={model} />}

          {<BindingArchiveForm model={model} />}
        </div>
      ) : null}
    </section>
  );
}

function BindingStateBadge({
  binding,
}: {
  binding: PlatformAuthProviderTenantBindingView;
}): React.JSX.Element {
  if (binding.archivedAt !== null) {
    return <Badge variant="outline">Archived</Badge>;
  }
  if (binding.enabled) {
    return <Badge>Tenant admission active</Badge>;
  }
  return binding.activationAvailable ? (
    <Badge variant="secondary">Ready to activate</Badge>
  ) : (
    <Badge variant="outline">Staged · not ready</Badge>
  );
}

function bindingRequiresActiveProvider(
  binding: PlatformAuthProviderTenantBindingView,
): boolean {
  return binding.enabled || binding.activationAvailable;
}

function BindingSelectField<T extends string>({
  disabled = false,
  id,
  label,
  onChange,
  options,
  value,
}: {
  disabled?: boolean;
  id: string;
  label: string;
  onChange: (value: T) => void;
  options: readonly (readonly [T, string])[];
  value: T;
}): React.JSX.Element {
  return (
    <FormField htmlFor={id} label={label}>
      <select
        className="platform-idp-select"
        disabled={disabled}
        id={id}
        value={value}
        onChange={(event) => {
          const selected = options.find(
            ([candidate]) => candidate === event.currentTarget.value,
          )?.[0];
          if (selected !== undefined) onChange(selected);
        }}
      >
        {options.map(([optionValue, optionLabel]) => (
          <option key={optionValue} value={optionValue}>
            {optionLabel}
          </option>
        ))}
      </select>
    </FormField>
  );
}

function BindingTextField({
  disabled = false,
  id,
  label,
  onChange,
  type = "text",
  value,
}: {
  disabled?: boolean;
  id: string;
  label: string;
  onChange: (value: string) => void;
  type?: "number" | "text";
  value: string;
}): React.JSX.Element {
  return (
    <FormField htmlFor={id} label={label}>
      <Input
        disabled={disabled}
        id={id}
        type={type}
        value={value}
        onChange={(event) => onChange(event.target.value)}
      />
    </FormField>
  );
}

function BindingFormFeedback({
  errors,
  requestError,
}: {
  errors: readonly string[];
  requestError: string | null;
}): React.JSX.Element | null {
  if (errors.length === 0 && !requestError) return null;
  return (
    <div className="platform-idp-binding-feedback">
      {errors.length > 0 ? (
        <FormValidationAlert
          errors={errors}
          title="Review the binding fields"
        />
      ) : null}
      {requestError ? <FocusedError message={requestError} /> : null}
    </div>
  );
}

function validateCreateDraft(draft: CreateBindingDraft): readonly string[] {
  const errors = [...validateBindingDraft(draft)];
  if (!canonicalUuidV7Pattern.test(draft.tenantId)) {
    errors.unshift("Tenant ID must be a canonical UUIDv7.");
  }
  return errors;
}

function validateBindingDraft(draft: BindingDraft): readonly string[] {
  const errors: string[] = [];
  if (!/^[a-z][a-z0-9_-]{2,63}$/.test(draft.loginKey)) {
    errors.push(
      "Tenant login key must contain 3-64 lowercase letters, numbers, underscores, or hyphens and start with a letter.",
    );
  }
  const priority = Number(draft.profilePriority);
  if (
    draft.profilePriority.trim() === "" ||
    !Number.isSafeInteger(priority) ||
    priority < 0 ||
    priority > 1_000_000
  ) {
    errors.push("Profile priority must be an integer from 0 to 1000000.");
  }
  const reasonError = validatePlatformAuthProviderAuditReason(
    draft.auditReason,
  );
  if (reasonError) errors.push(reasonError);
  return errors;
}

function isAbortError(caught: unknown): boolean {
  return caught instanceof DOMException && caught.name === "AbortError";
}

function humanizeBindingPolicy(value: string): string {
  return value
    .split("_")
    .map((part) => `${part.slice(0, 1).toUpperCase()}${part.slice(1)}`)
    .join(" ");
}

const canonicalUuidV7Pattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

function BindingCreatePanel({
  model,
}: {
  model: React.ComponentProps<
    typeof PlatformAuthProviderTenantBindingsView
  >["model"];
}): React.ReactNode {
  const { canCreate, createOpen } = model;
  return createOpen && canCreate ? <BindingCreateForm model={model} /> : null;
}

function BindingActionsPanel({
  model,
}: {
  model: React.ComponentProps<
    typeof PlatformAuthProviderTenantBindingsView
  >["model"];
}): React.ReactNode {
  const { canMutate, selected } = model;
  if (!selected) return null;

  return canMutate && selected.value.archivedAt === null ? (
    <BindingActions model={model} />
  ) : null;
}

function BindingMetadataPanel({
  model,
}: {
  model: React.ComponentProps<
    typeof PlatformAuthProviderTenantBindingsView
  >["model"];
}): React.ReactNode {
  const { canMutate, editDraft } = model;
  return editDraft && canMutate ? <BindingMetadataForm model={model} /> : null;
}

function BindingLifecyclePanel({
  model,
}: {
  model: React.ComponentProps<
    typeof PlatformAuthProviderTenantBindingsView
  >["model"];
}): React.ReactNode {
  const {
    canMutate,
    lifecycleCommand,
    providerEnabled,
    providerKind,
    selected,
  } = model;
  if (!selected) return null;

  return lifecycleCommand &&
    canMutate &&
    providerKind !== "saml" &&
    providerEnabled !== false ? (
    <BindingLifecycleForm model={model} />
  ) : null;
}

interface PlatformAuthProviderTenantBindingsState {
  listState: BindingListState;
  listRevision: number;
  paginationError: string | null;
  loadingMore: boolean;
  createOpen: boolean;
  createDraft: CreateBindingDraft;
  detailState: BindingDetailState;
  editDraft: BindingDraft | null;
  archiveOpen: boolean;
  archiveReason: string;
  archiveConfirmation: string;
  lifecycleCommand: BindingLifecycleCommand | null;
  lifecycleReason: string;
  lifecycleConfirmation: string;
  jitMode: BindingJitMode;
  noMatchPolicy: BindingNoMatchPolicy;
  validationErrors: readonly string[];
  mutationError: string | null;
  submitting:
    "activate" | "archive" | "create" | "deactivate" | "update" | null;
  providerActiveObserved: boolean;
}

function BindingInventoryHeading({
  model,
}: {
  model: React.ComponentProps<
    typeof PlatformAuthProviderTenantBindingsView
  >["model"];
}): React.ReactNode {
  const {
    canCreate,
    detailAbortRef,
    detailEpochRef,
    providerArchived,
    providerExecutionActive,
    providerMutationBusy,
    setArchiveOpen,
    setCreateOpen,
    setDetailState,
    setEditDraft,
    setLifecycleCommand,
    setLifecycleConfirmation,
    setLifecycleReason,
    setMutationError,
    setValidationErrors,
    submitting,
    titleId,
  } = model;
  return (
    <div className="platform-idp-section-heading">
      <div>
        <p className="section-label">Cross-boundary admission</p>
        <h3 id={titleId}>Tenant bindings</h3>
      </div>
      {canCreate ? (
        <Button
          type="button"
          size="sm"
          variant="outline"
          disabled={submitting !== null}
          onClick={() => {
            detailAbortRef.current?.abort();
            detailAbortRef.current = null;
            detailEpochRef.current += 1;
            setCreateOpen((open) => !open);
            setDetailState({ kind: "idle" });
            setEditDraft(null);
            setArchiveOpen(false);
            setLifecycleCommand(null);
            setLifecycleReason("");
            setLifecycleConfirmation("");
            setValidationErrors([]);
            setMutationError(null);
          }}
        >
          <Plus aria-hidden="true" /> Create tenant binding
        </Button>
      ) : (
        <Badge variant="outline">
          <ShieldCheck aria-hidden="true" />
          {providerArchived
            ? "Provider archived"
            : providerMutationBusy
              ? "Provider mutation in progress"
              : providerExecutionActive
                ? "Provider execution active"
                : "Read-only authority"}
        </Badge>
      )}
    </div>
  );
}

function BindingInventoryTable({
  model,
}: {
  model: React.ComponentProps<
    typeof PlatformAuthProviderTenantBindingsView
  >["model"];
}): React.ReactNode {
  const { canMutate, inspectBinding, listState, submitting } = model;
  return listState.kind === "ready" ? (
    listState.items.length === 0 ? (
      <div className="platform-idp-binding-empty">
        <Link2 aria-hidden="true" />
        <p>No tenant bindings recorded.</p>
      </div>
    ) : (
      <div className="platform-idp-table-wrap">
        <Table className="platform-idp-binding-table">
          <TableColumnHeaders
            columns={["Tenant", "Login key", "Priority", "State"]}
            actionLabel="Action"
            actionPresentation="visible"
          />
          <TableBody>
            {listState.items.map((binding) => (
              <TableRow key={binding.id}>
                <TableCell>
                  <div className="platform-idp-provider-cell">
                    <strong>{binding.tenant.name}</strong>
                    <code>{binding.tenant.slug}</code>
                  </div>
                </TableCell>
                <TableCell>
                  <code>{binding.loginKey}</code>
                </TableCell>
                <TableCell>{binding.profilePriority}</TableCell>
                <TableCell>
                  <BindingStateBadge binding={binding} />
                </TableCell>
                <TableCell className="text-right">
                  <Button
                    type="button"
                    size="sm"
                    variant="outline"
                    aria-label={`${canMutate ? "Manage" : "Inspect"} ${binding.tenant.name} (${binding.loginKey}) binding`}
                    disabled={submitting !== null}
                    onClick={() => void inspectBinding(binding.id)}
                  >
                    {canMutate ? "Manage binding" : "Inspect binding"}
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
    )
  ) : null;
}

function BindingArchiveForm({
  model,
}: {
  model: React.ComponentProps<
    typeof PlatformAuthProviderTenantBindingsView
  >["model"];
}): React.ReactNode {
  const {
    archiveBinding,
    archiveConfirmation,
    archiveOpen,
    archiveReason,
    canMutate,
    mutationError,
    selected,
    setArchiveConfirmation,
    setArchiveOpen,
    setArchiveReason,
    submitting,
    validationErrors,
  } = model;
  if (!selected) return null;
  return archiveOpen && canMutate && !selected.value.enabled ? (
    <form
      className="platform-idp-action-form platform-idp-archive-form"
      aria-label="Archive tenant binding"
      aria-busy={submitting === "archive"}
      onSubmit={(event) => void archiveBinding(event)}
    >
      <h4>Archive binding permanently</h4>
      <BindingTextField
        disabled={submitting !== null}
        id="platform-idp-binding-archive-reason"
        label="Binding audit reason"
        value={archiveReason}
        onChange={setArchiveReason}
      />
      <BindingTextField
        disabled={submitting !== null}
        id="platform-idp-binding-archive-confirmation"
        label={`Type ${selected.value.loginKey} to confirm`}
        value={archiveConfirmation}
        onChange={setArchiveConfirmation}
      />
      <BindingFormFeedback
        errors={validationErrors}
        requestError={mutationError}
      />
      <div className="platform-idp-form-actions">
        <Button
          type="button"
          variant="ghost"
          disabled={submitting !== null}
          onClick={() => setArchiveOpen(false)}
        >
          Cancel archival
        </Button>
        <Button
          type="submit"
          variant="destructive"
          disabled={submitting !== null}
        >
          <Archive aria-hidden="true" />
          {submitting === "archive" ? "Archiving…" : "Archive binding"}
        </Button>
      </div>
    </form>
  ) : null;
}

function BindingCreateForm({
  model,
}: {
  model: React.ComponentProps<typeof BindingCreatePanel>["model"];
}): React.ReactNode {
  const {
    createBinding,
    createDraft,
    idempotencyBindingRef,
    mutationError,
    setCreateDraft,
    setCreateOpen,
    setMutationError,
    setValidationErrors,
    submitting,
    validationErrors,
  } = model;
  return (
    <form
      className="platform-idp-action-form"
      aria-label="Create tenant binding"
      aria-busy={submitting === "create"}
      onSubmit={(event) => void createBinding(event)}
    >
      <h4>Create disabled-only tenant binding</h4>
      <div className="platform-idp-binding-form-grid">
        <BindingTextField
          disabled={submitting !== null}
          id="platform-idp-binding-tenant-id"
          label="Tenant ID"
          value={createDraft.tenantId}
          onChange={(tenantId) => setCreateDraft({ ...createDraft, tenantId })}
        />
        <BindingTextField
          disabled={submitting !== null}
          id="platform-idp-binding-create-key"
          label="Tenant login key"
          value={createDraft.loginKey}
          onChange={(loginKey) => setCreateDraft({ ...createDraft, loginKey })}
        />
        <BindingTextField
          disabled={submitting !== null}
          id="platform-idp-binding-create-priority"
          label="Profile priority"
          type="number"
          value={createDraft.profilePriority}
          onChange={(profilePriority) =>
            setCreateDraft({ ...createDraft, profilePriority })
          }
        />
        <BindingTextField
          disabled={submitting !== null}
          id="platform-idp-binding-create-reason"
          label="Binding audit reason"
          value={createDraft.auditReason}
          onChange={(auditReason) =>
            setCreateDraft({ ...createDraft, auditReason })
          }
        />
      </div>
      <BindingFormFeedback
        errors={validationErrors}
        requestError={mutationError}
      />
      <div className="platform-idp-form-actions">
        <Button
          type="button"
          variant="ghost"
          disabled={submitting !== null}
          onClick={() => {
            setCreateOpen(false);
            setCreateDraft(emptyCreateDraft);
            setValidationErrors([]);
            setMutationError(null);
            idempotencyBindingRef.current = null;
          }}
        >
          Cancel
        </Button>
        <Button type="submit" disabled={submitting !== null}>
          <Plus aria-hidden="true" />
          {submitting === "create" ? "Creating…" : "Create staged binding"}
        </Button>
      </div>
    </form>
  );
}

function BindingActions({
  model,
}: {
  model: React.ComponentProps<typeof BindingActionsPanel>["model"];
}): React.ReactNode {
  const {
    String,
    providerEnabled,
    providerKind,
    selected,
    setArchiveConfirmation,
    setArchiveOpen,
    setArchiveReason,
    setEditDraft,
    setJitMode,
    setLifecycleCommand,
    setLifecycleConfirmation,
    setLifecycleReason,
    setMutationError,
    setNoMatchPolicy,
    setValidationErrors,
    submitting,
  } = model;
  if (!selected) return null;
  return (
    <div className="platform-idp-action-buttons">
      {!selected.value.enabled ? (
        <Button
          type="button"
          variant="outline"
          disabled={submitting !== null}
          onClick={() => {
            setEditDraft({
              auditReason: "",
              loginKey: selected.value.loginKey,
              profilePriority: String(selected.value.profilePriority),
            });
            setArchiveOpen(false);
            setLifecycleCommand(null);
            setLifecycleReason("");
            setLifecycleConfirmation("");
            setValidationErrors([]);
            setMutationError(null);
          }}
        >
          <Pencil aria-hidden="true" /> Edit key and priority
        </Button>
      ) : null}
      {providerKind !== "saml" &&
      providerEnabled !== false &&
      (selected.value.enabled || selected.value.activationAvailable) ? (
        <Button
          type="button"
          variant={selected.value.enabled ? "destructive" : "default"}
          disabled={submitting !== null}
          onClick={() => {
            setEditDraft(null);
            setArchiveOpen(false);
            setArchiveReason("");
            setArchiveConfirmation("");
            setLifecycleCommand(
              selected.value.enabled ? "deactivate" : "activate",
            );
            setLifecycleReason("");
            setLifecycleConfirmation("");
            setJitMode(selected.value.jitMode);
            setNoMatchPolicy(selected.value.noMatchPolicy);
            setValidationErrors([]);
            setMutationError(null);
          }}
        >
          {selected.value.enabled
            ? "Deactivate tenant admission"
            : "Activate tenant admission"}
        </Button>
      ) : null}
      {!selected.value.enabled ? (
        <Button
          type="button"
          variant="destructive"
          disabled={submitting !== null}
          onClick={() => {
            setEditDraft(null);
            setLifecycleCommand(null);
            setLifecycleReason("");
            setLifecycleConfirmation("");
            setArchiveOpen(true);
            setArchiveReason("");
            setArchiveConfirmation("");
            setValidationErrors([]);
            setMutationError(null);
          }}
        >
          <Archive aria-hidden="true" /> Archive binding
        </Button>
      ) : null}
    </div>
  );
}

function BindingMetadataForm({
  model,
}: {
  model: React.ComponentProps<typeof BindingMetadataPanel>["model"];
}): React.ReactNode {
  const {
    editDraft,
    mutationError,
    setEditDraft,
    submitting,
    updateBinding,
    validationErrors,
  } = model;
  if (!editDraft) return null;
  return (
    <form
      className="platform-idp-action-form"
      aria-label="Edit tenant binding"
      aria-busy={submitting === "update"}
      onSubmit={(event) => void updateBinding(event)}
    >
      <h4>Edit binding metadata</h4>
      <div className="platform-idp-binding-form-grid">
        <BindingTextField
          disabled={submitting !== null}
          id="platform-idp-binding-edit-key"
          label="Tenant login key"
          value={editDraft.loginKey}
          onChange={(loginKey) => setEditDraft({ ...editDraft, loginKey })}
        />
        <BindingTextField
          disabled={submitting !== null}
          id="platform-idp-binding-edit-priority"
          label="Profile priority"
          type="number"
          value={editDraft.profilePriority}
          onChange={(profilePriority) =>
            setEditDraft({ ...editDraft, profilePriority })
          }
        />
        <BindingTextField
          disabled={submitting !== null}
          id="platform-idp-binding-edit-reason"
          label="Binding audit reason"
          value={editDraft.auditReason}
          onChange={(auditReason) =>
            setEditDraft({ ...editDraft, auditReason })
          }
        />
      </div>
      <BindingFormFeedback
        errors={validationErrors}
        requestError={mutationError}
      />
      <div className="platform-idp-form-actions">
        <Button
          type="button"
          variant="ghost"
          disabled={submitting !== null}
          onClick={() => setEditDraft(null)}
        >
          Cancel edit
        </Button>
        <Button type="submit" disabled={submitting !== null}>
          <Save aria-hidden="true" />
          {submitting === "update" ? "Saving…" : "Save binding metadata"}
        </Button>
      </div>
    </form>
  );
}

function BindingLifecycleForm({
  model,
}: {
  model: React.ComponentProps<typeof BindingLifecyclePanel>["model"];
}): React.ReactNode {
  const {
    changeBindingAccess,
    jitMode,
    lifecycleCommand,
    lifecycleConfirmation,
    lifecycleReason,
    mutationError,
    noMatchPolicy,
    providerAccountMode,
    selected,
    setJitMode,
    setLifecycleCommand,
    setLifecycleConfirmation,
    setLifecycleReason,
    setMutationError,
    setNoMatchPolicy,
    setValidationErrors,
    submitting,
    validationErrors,
  } = model;
  if (!selected) return null;
  return (
    <form
      className="platform-idp-action-form"
      aria-label={`${lifecycleCommand === "activate" ? "Activate" : "Deactivate"} tenant binding`}
      aria-busy={submitting === lifecycleCommand}
      onSubmit={(event) => void changeBindingAccess(event)}
    >
      <div>
        <h4>
          {lifecycleCommand === "activate"
            ? "Activate tenant admission"
            : "Deactivate tenant admission"}
        </h4>
        <p>
          This command changes a tenant-scoped access epoch. It never creates
          roles, groups, teams, or platform authority.
        </p>
      </div>
      {lifecycleCommand === "activate" ? (
        <div className="platform-idp-binding-form-grid">
          <BindingSelectField
            disabled={submitting !== null}
            id="platform-idp-binding-jit-mode"
            label="Tenant membership JIT"
            value={jitMode}
            options={[
              ["disabled", "Disabled"],
              ...(providerAccountMode !== undefined &&
              providerAccountMode !== "create"
                ? []
                : ([["create", "Create tenant membership/access"]] as const)),
            ]}
            onChange={setJitMode}
          />
          <BindingSelectField
            disabled={submitting !== null}
            id="platform-idp-binding-no-match-policy"
            label="When no tenant authority matches"
            value={noMatchPolicy}
            options={[
              ["deny", "Deny access"],
              [
                "provider_access_only",
                "Provider access only (RBAC still required)",
              ],
            ]}
            onChange={setNoMatchPolicy}
          />
        </div>
      ) : null}
      <BindingTextField
        disabled={submitting !== null}
        id="platform-idp-binding-lifecycle-reason"
        label="Binding audit reason"
        value={lifecycleReason}
        onChange={setLifecycleReason}
      />
      <BindingTextField
        disabled={submitting !== null}
        id="platform-idp-binding-lifecycle-confirmation"
        label={`Type ${selected.value.loginKey} to confirm`}
        value={lifecycleConfirmation}
        onChange={setLifecycleConfirmation}
      />
      <BindingFormFeedback
        errors={validationErrors}
        requestError={mutationError}
      />
      <div className="platform-idp-form-actions">
        <Button
          type="button"
          variant="ghost"
          disabled={submitting !== null}
          onClick={() => {
            setLifecycleCommand(null);
            setLifecycleReason("");
            setLifecycleConfirmation("");
            setValidationErrors([]);
            setMutationError(null);
          }}
        >
          Cancel {lifecycleCommand}
        </Button>
        <Button
          type="submit"
          variant={
            lifecycleCommand === "deactivate" ? "destructive" : "default"
          }
          disabled={submitting !== null}
        >
          {submitting === lifecycleCommand
            ? "Submitting…"
            : lifecycleCommand === "activate"
              ? "Activate tenant admission"
              : "Deactivate tenant admission"}
        </Button>
      </div>
    </form>
  );
}

function BindingInventoryError({
  model,
}: {
  model: React.ComponentProps<
    typeof PlatformAuthProviderTenantBindingsView
  >["model"];
}): React.ReactNode {
  const { listState, setListRevision } = model;
  return listState.kind === "error" ? (
    <div className="platform-idp-load-error">
      <FocusedError message={listState.message} />
      <Button
        type="button"
        variant="outline"
        onClick={() => setListRevision((revision) => revision + 1)}
      >
        <RefreshCw aria-hidden="true" /> Retry tenant bindings
      </Button>
    </div>
  ) : null;
}

function BindingInventoryPagination({
  model,
}: {
  model: React.ComponentProps<
    typeof PlatformAuthProviderTenantBindingsView
  >["model"];
}): React.ReactNode {
  const { listState, loadMore, loadingMore } = model;
  return listState.kind === "ready" && listState.nextCursor ? (
    <div className="platform-idp-pagination">
      <Button
        type="button"
        variant="outline"
        disabled={loadingMore}
        onClick={() => void loadMore()}
      >
        {loadingMore ? "Loading…" : "Load more bindings"}
      </Button>
    </div>
  ) : null;
}

function BindingDetailError({
  model,
}: {
  model: React.ComponentProps<
    typeof PlatformAuthProviderTenantBindingsView
  >["model"];
}): React.ReactNode {
  const { detailState, inspectBinding } = model;
  return detailState.kind === "error" ? (
    <div className="platform-idp-load-error">
      <FocusedError message={detailState.message} />
      <Button
        type="button"
        variant="outline"
        onClick={() => void inspectBinding(detailState.bindingId)}
      >
        <RefreshCw aria-hidden="true" /> Retry binding detail
      </Button>
    </div>
  ) : null;
}

function BindingDetailHeading({
  model,
}: {
  model: React.ComponentProps<
    typeof PlatformAuthProviderTenantBindingsView
  >["model"];
}): React.ReactNode {
  const { selected } = model;
  if (!selected) return null;
  return (
    <div>
      <span>
        <strong>{selected.value.tenant.name}</strong>
        <small>
          {selected.value.tenant.status} tenant · If-Match {selected.etag}
        </small>
      </span>
      <Badge variant="outline">
        {selected.value.enabled
          ? "Tenant admission active"
          : selected.value.archivedAt !== null
            ? "Archived"
            : selected.value.activationAvailable
              ? "Ready to activate"
              : "Staged · not ready"}
      </Badge>
    </div>
  );
}

function BindingFacts({
  model,
}: {
  model: React.ComponentProps<
    typeof PlatformAuthProviderTenantBindingsView
  >["model"];
}): React.ReactNode {
  const { selected } = model;
  if (!selected) return null;
  return (
    <dl className="platform-idp-binding-facts">
      <div>
        <dt>JIT mode</dt>
        <dd>{humanizeBindingPolicy(selected.value.jitMode)}</dd>
      </div>
      <div>
        <dt>No-match policy</dt>
        <dd>{humanizeBindingPolicy(selected.value.noMatchPolicy)}</dd>
      </div>
      <div>
        <dt>Access epoch</dt>
        <dd>{selected.value.currentAccessEpochId ?? "No live access epoch"}</dd>
      </div>
    </dl>
  );
}
