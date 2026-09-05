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
  TableHead,
  TableHeader,
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
import { useEffect, useId, useRef, useState } from "react";

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

export function PlatformAuthProviderTenantBindings({
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
}: PlatformAuthProviderTenantBindingsProps): React.JSX.Element {
  const titleId = useId();
  const [listState, setListState] = useState<BindingListState>({
    kind: "loading",
  });
  const [listRevision, setListRevision] = useState(0);
  const [paginationError, setPaginationError] = useState<string | null>(null);
  const [loadingMore, setLoadingMore] = useState(false);
  const [createOpen, setCreateOpen] = useState(false);
  const [createDraft, setCreateDraft] =
    useState<CreateBindingDraft>(emptyCreateDraft);
  const [detailState, setDetailState] = useState<BindingDetailState>({
    kind: "idle",
  });
  const [editDraft, setEditDraft] = useState<BindingDraft | null>(null);
  const [archiveOpen, setArchiveOpen] = useState(false);
  const [archiveReason, setArchiveReason] = useState("");
  const [archiveConfirmation, setArchiveConfirmation] = useState("");
  const [lifecycleCommand, setLifecycleCommand] =
    useState<BindingLifecycleCommand | null>(null);
  const [lifecycleReason, setLifecycleReason] = useState("");
  const [lifecycleConfirmation, setLifecycleConfirmation] = useState("");
  const [jitMode, setJitMode] = useState<BindingJitMode>("disabled");
  const [noMatchPolicy, setNoMatchPolicy] =
    useState<BindingNoMatchPolicy>("deny");
  const [validationErrors, setValidationErrors] = useState<readonly string[]>(
    [],
  );
  const [mutationError, setMutationError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState<
    "activate" | "archive" | "create" | "deactivate" | "update" | null
  >(null);
  const [providerActiveObserved, setProviderActiveObserved] = useState(false);
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
  contextRef.current = {
    canManage,
    canRead,
    providerArchived,
    providerExecutionActive,
    providerMutationBusy,
    providerId,
    sessionId,
  };

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
    setCreateOpen(false);
    setCreateDraft(emptyCreateDraft);
    setDetailState({ kind: "idle" });
    setEditDraft(null);
    setArchiveOpen(false);
    setArchiveReason("");
    setArchiveConfirmation("");
    setLifecycleCommand(null);
    setLifecycleReason("");
    setLifecycleConfirmation("");
    setJitMode("disabled");
    setNoMatchPolicy("deny");
    setValidationErrors([]);
    setMutationError(null);
    setSubmitting(null);
    setProviderActiveObserved(false);
    setPaginationError(null);
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
  }, [providerEnabled]);

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
    setCreateOpen(false);
    setCreateDraft(emptyCreateDraft);
    setListState({ kind: "loading" });
    setDetailState({ kind: "idle" });
    setEditDraft(null);
    setArchiveOpen(false);
    setArchiveReason("");
    setArchiveConfirmation("");
    setLifecycleCommand(null);
    setLifecycleReason("");
    setLifecycleConfirmation("");
    setMutationError(null);
    setValidationErrors([]);
    setSubmitting(null);
    setPaginationError(null);
    setLoadingMore(false);
    idempotencyBindingRef.current = null;
  }, [canRead, onMutationBusyChange]);

  useEffect(() => {
    if (canManage && !providerArchived && !providerMutationBusy) return;
    const mutationWasPending = mutationLockRef.current !== null;
    mutationLockRef.current = null;
    setSubmitting(null);
    if (mutationWasPending) onMutationBusyChange(false);
    setCreateOpen(false);
    setCreateDraft(emptyCreateDraft);
    setEditDraft(null);
    setArchiveOpen(false);
    setArchiveReason("");
    setArchiveConfirmation("");
    setLifecycleCommand(null);
    setLifecycleReason("");
    setLifecycleConfirmation("");
    setJitMode("disabled");
    setNoMatchPolicy("deny");
    setValidationErrors([]);
    setMutationError(null);
    idempotencyBindingRef.current = null;
  }, [canManage, onMutationBusyChange, providerArchived, providerMutationBusy]);

  useEffect(() => {
    if (!providerExecutionActive) return;
    setCreateOpen(false);
    setCreateDraft(emptyCreateDraft);
    idempotencyBindingRef.current = null;
    if (submitting === "create") {
      mutationLockRef.current = null;
      setSubmitting(null);
      onMutationBusyChange(false);
    }
  }, [onMutationBusyChange, providerExecutionActive, submitting]);

  useEffect(() => {
    if (externalRefreshRef.current === refreshRevision) return;
    externalRefreshRef.current = refreshRevision;
    const bindingId =
      detailState.kind === "ready"
        ? detailState.value.value.id
        : detailState.kind === "loading" || detailState.kind === "error"
          ? detailState.bindingId
          : null;
    if (bindingId !== null && canRead) void inspectBinding(bindingId);
  }, [canRead, refreshRevision]);

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
    setListState({ kind: "loading" });
    setLoadingMore(true);
    setPaginationError(null);
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
  }, [api, canRead, listRevision, providerId, refreshRevision, sessionId]);

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

  function handleAuthorizationError(caught: unknown): boolean {
    if (caught instanceof PhaseTwoApiError && caught.status === 401) {
      onUnauthenticated();
      return true;
    }
    if (caught instanceof PhaseTwoApiError && caught.status === 403) {
      onPermissionError();
    }
    return false;
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
    setLoadingMore(true);
    setPaginationError(null);
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
    setCreateOpen(false);
    setDetailState({ bindingId, kind: "loading" });
    setEditDraft(null);
    setArchiveOpen(false);
    setArchiveReason("");
    setArchiveConfirmation("");
    setLifecycleCommand(null);
    setLifecycleReason("");
    setLifecycleConfirmation("");
    setValidationErrors([]);
    setMutationError(null);
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
    setValidationErrors(errors);
    setMutationError(null);
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
      setCreateDraft(emptyCreateDraft);
      setCreateOpen(false);
      setDetailState({ kind: "ready", value: created });
      setListRevision((revision) => revision + 1);
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
        setCreateDraft(emptyCreateDraft);
        setCreateOpen(false);
        setValidationErrors([]);
        setMutationError(null);
        setListRevision((revision) => revision + 1);
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
    setValidationErrors(errors);
    setMutationError(null);
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
      setEditDraft(null);
      setValidationErrors([]);
      setListRevision((revision) => revision + 1);
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
    setValidationErrors(errors);
    setMutationError(null);
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
      setLifecycleCommand(null);
      setLifecycleReason("");
      setLifecycleConfirmation("");
      setValidationErrors([]);
      setListRevision((revision) => revision + 1);
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
        setLifecycleCommand(null);
        setLifecycleReason("");
        setLifecycleConfirmation("");
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
    setValidationErrors(errors);
    setMutationError(null);
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
      setDetailState({ kind: "idle" });
      setArchiveOpen(false);
      setArchiveReason("");
      setArchiveConfirmation("");
      setListRevision((revision) => revision + 1);
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
    return (
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
    );
  }

  const canMutate = canManage && !providerArchived && !providerMutationBusy;
  const canCreate = canMutate && !providerExecutionActive;
  const selected = detailState.kind === "ready" ? detailState.value : null;

  return (
    <section className="platform-idp-bindings" aria-labelledby={titleId}>
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

      <Alert className="platform-idp-binding-gate">
        <ShieldAlert aria-hidden="true" />
        <AlertTitle>Explicit tenant admission boundary</AlertTitle>
        <AlertDescription>
          Ready bindings can be activated with an explicit JIT and no-match
          policy. Activation never creates platform roles or enables direct
          platform login.
        </AlertDescription>
      </Alert>

      {createOpen && canCreate ? (
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
              onChange={(tenantId) =>
                setCreateDraft({ ...createDraft, tenantId })
              }
            />
            <BindingTextField
              disabled={submitting !== null}
              id="platform-idp-binding-create-key"
              label="Tenant login key"
              value={createDraft.loginKey}
              onChange={(loginKey) =>
                setCreateDraft({ ...createDraft, loginKey })
              }
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
      ) : null}

      {listState.kind === "loading" ? (
        <p role="status">Loading tenant bindings…</p>
      ) : null}
      {listState.kind === "error" ? (
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
      ) : null}
      {listState.kind === "ready" ? (
        listState.items.length === 0 ? (
          <div className="platform-idp-binding-empty">
            <Link2 aria-hidden="true" />
            <p>No tenant bindings recorded.</p>
          </div>
        ) : (
          <div className="platform-idp-table-wrap">
            <Table className="platform-idp-binding-table">
              <TableHeader>
                <TableRow>
                  <TableHead>Tenant</TableHead>
                  <TableHead>Login key</TableHead>
                  <TableHead>Priority</TableHead>
                  <TableHead>State</TableHead>
                  <TableHead className="text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
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
      ) : null}
      {paginationError ? <FocusedError message={paginationError} /> : null}
      {listState.kind === "ready" && listState.nextCursor ? (
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
      ) : null}

      {detailState.kind === "loading" ? (
        <p role="status">Loading tenant-binding detail…</p>
      ) : null}
      {detailState.kind === "error" ? (
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
      ) : null}
      {selected ? (
        <div className="platform-idp-binding-detail">
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
              <dd>
                {selected.value.currentAccessEpochId ?? "No live access epoch"}
              </dd>
            </div>
          </dl>
          {canMutate && selected.value.archivedAt === null ? (
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
          ) : null}

          {editDraft && canMutate ? (
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
                  onChange={(loginKey) =>
                    setEditDraft({ ...editDraft, loginKey })
                  }
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
                  {submitting === "update"
                    ? "Saving…"
                    : "Save binding metadata"}
                </Button>
              </div>
            </form>
          ) : null}

          {lifecycleCommand &&
          canMutate &&
          providerKind !== "saml" &&
          providerEnabled !== false ? (
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
                  This command changes a tenant-scoped access epoch. It never
                  creates roles, groups, teams, or platform authority.
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
                        : ([
                            ["create", "Create tenant membership/access"],
                          ] as const)),
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
                    lifecycleCommand === "deactivate"
                      ? "destructive"
                      : "default"
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
          ) : null}

          {archiveOpen && canMutate && !selected.value.enabled ? (
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
          ) : null}
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
        <Alert variant="destructive">
          <ShieldAlert aria-hidden="true" />
          <AlertTitle>Review the binding fields</AlertTitle>
          <AlertDescription>
            <ul>
              {errors.map((error) => (
                <li key={error}>{error}</li>
              ))}
            </ul>
          </AlertDescription>
        </Alert>
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
