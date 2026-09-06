import {
  Alert,
  AlertDescription,
  AlertTitle,
} from "@periapsis/ui/components/ui/alert";
import { Badge } from "@periapsis/ui/components/ui/badge";
import { Button } from "@periapsis/ui/components/ui/button";
import { Checkbox } from "@periapsis/ui/components/ui/checkbox";
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
  Fingerprint,
  Link2,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  UserRoundX,
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
import { TableColumnHeaders } from "../components/table-column-headers";
import { FormValidationAlert } from "./form-validation-alert";
import { reduceWorkspaceState } from "./workspace-state";

import { FocusedError } from "../components/focused-error";
import { FormField } from "../components/form-field";
import {
  describePhaseTwoError,
  PhaseTwoApiError,
  type PhaseTwoApi,
  type PlatformAuthProviderAccountView,
  type VersionedView,
} from "../lib/phase-two-types";
import {
  validatePlatformIdentityAccountPrelinkConfirmation,
  validatePlatformIdentityAccountPrelinkDraft,
  validatePlatformIdentityAccountPrelinkIssuer,
  validatePlatformIdentityAccountRetirement,
  type PlatformIdentityAccountPrelinkConfirmation,
  type PlatformIdentityAccountPrelinkDraft,
} from "./platform-auth-provider-account-model";

const dateTimeFormatter = new Intl.DateTimeFormat(undefined, {
  day: "numeric",
  hour: "2-digit",
  minute: "2-digit",
  month: "short",
  timeZoneName: "short",
  year: "numeric",
});

type AccountListState =
  | { kind: "error"; message: string }
  | { kind: "loading" }
  | {
      items: readonly PlatformAuthProviderAccountView[];
      kind: "ready";
      nextCursor?: string;
    };

type RetirementState =
  | { kind: "error"; accountId: string; message: string }
  | { kind: "idle" }
  | { kind: "loading"; accountId: string }
  | {
      confirmation: string;
      current: VersionedView<PlatformAuthProviderAccountView>;
      errors: readonly string[];
      kind: "ready";
      reason: string;
    };

interface PlatformAuthProviderAccountsProps {
  allowWriteOnlyIssuer?: boolean;
  api: PhaseTwoApi;
  canManage: boolean;
  canRead: boolean;
  csrfToken: string;
  onMutationBusyChange: (busy: boolean) => void;
  onNotice: (notice: { message: string; tone: "success" | "warning" }) => void;
  onPermissionError: () => void;
  onUnauthenticated: () => void;
  prelinkIssuer?: string;
  providerId: string;
  providerMutationBusy: boolean;
  providerVersion: number;
  refreshRevision?: number;
  sessionId: string;
}

const emptyPrelinkDraft: PlatformIdentityAccountPrelinkDraft = {
  auditReason: "",
  subject: "",
  userId: "",
};

const emptyPrelinkConfirmation: PlatformIdentityAccountPrelinkConfirmation = {
  subject: "",
  userId: "",
};

export function PlatformAuthProviderAccounts(
  props: PlatformAuthProviderAccountsProps,
): React.JSX.Element {
  const model = usePlatformAuthProviderAccountsModel(props);
  return <PlatformAuthProviderAccountsView model={model.data} />;
}

function usePlatformAuthProviderAccountsModel({
  allowWriteOnlyIssuer = false,
  api,
  canManage,
  canRead,
  csrfToken,
  onMutationBusyChange,
  onNotice,
  onPermissionError,
  onUnauthenticated,
  prelinkIssuer,
  providerId,
  providerMutationBusy,
  providerVersion,
  refreshRevision = 0,
  sessionId,
}: PlatformAuthProviderAccountsProps) {
  const titleId = useId();
  const prelinkRegionId = useId();
  const prelinkTitleId = useId();
  const prelinkReviewTitleId = useId();
  const retirementRegionId = useId();
  const retirementTitleId = useId();
  const [workspaceState, updateWorkspaceState] = useReducer(
    reduceWorkspaceState<PlatformAuthProviderAccountsState>,
    undefined,
    (): PlatformAuthProviderAccountsState => ({
      includeRetired: true,
      listState: {
        kind: "loading",
      },
      listRevision: 0,
      loadingMore: false,
      paginationError: null,
      prelinkOpen: false,
      prelinkDraft: emptyPrelinkDraft,
      prelinkIssuerDraft: "",
      prelinkConfirmation: null,
      prelinkErrors: [],
      retirement: {
        kind: "idle",
      },
      mutationError: null,
      submitting: null,
    }),
  );
  const {
    includeRetired,
    listState,
    listRevision,
    loadingMore,
    paginationError,
    prelinkOpen,
    prelinkDraft,
    prelinkIssuerDraft,
    prelinkConfirmation,
    prelinkErrors,
    retirement,
    mutationError,
    submitting,
  } = workspaceState;
  const {
    setIncludeRetired,
    setListState,
    setListRevision,
    setLoadingMore,
    setPaginationError,
    setPrelinkOpen,
    setPrelinkConfirmation,
    setPrelinkErrors,
    setRetirement,
    setMutationError,
    setSubmitting,
  } = useMemo(
    () => ({
      setIncludeRetired: (
        value: React.SetStateAction<
          PlatformAuthProviderAccountsState["includeRetired"]
        >,
      ) => updateWorkspaceState({ includeRetired: value }),
      setListState: (
        value: React.SetStateAction<
          PlatformAuthProviderAccountsState["listState"]
        >,
      ) => updateWorkspaceState({ listState: value }),
      setListRevision: (
        value: React.SetStateAction<
          PlatformAuthProviderAccountsState["listRevision"]
        >,
      ) => updateWorkspaceState({ listRevision: value }),
      setLoadingMore: (
        value: React.SetStateAction<
          PlatformAuthProviderAccountsState["loadingMore"]
        >,
      ) => updateWorkspaceState({ loadingMore: value }),
      setPaginationError: (
        value: React.SetStateAction<
          PlatformAuthProviderAccountsState["paginationError"]
        >,
      ) => updateWorkspaceState({ paginationError: value }),
      setPrelinkOpen: (
        value: React.SetStateAction<
          PlatformAuthProviderAccountsState["prelinkOpen"]
        >,
      ) => updateWorkspaceState({ prelinkOpen: value }),
      setPrelinkConfirmation: (
        value: React.SetStateAction<
          PlatformAuthProviderAccountsState["prelinkConfirmation"]
        >,
      ) => updateWorkspaceState({ prelinkConfirmation: value }),
      setPrelinkErrors: (
        value: React.SetStateAction<
          PlatformAuthProviderAccountsState["prelinkErrors"]
        >,
      ) => updateWorkspaceState({ prelinkErrors: value }),
      setRetirement: (
        value: React.SetStateAction<
          PlatformAuthProviderAccountsState["retirement"]
        >,
      ) => updateWorkspaceState({ retirement: value }),
      setMutationError: (
        value: React.SetStateAction<
          PlatformAuthProviderAccountsState["mutationError"]
        >,
      ) => updateWorkspaceState({ mutationError: value }),
      setSubmitting: (
        value: React.SetStateAction<
          PlatformAuthProviderAccountsState["submitting"]
        >,
      ) => updateWorkspaceState({ submitting: value }),
    }),
    [updateWorkspaceState],
  );

  const contextRef = useRef({
    canManage,
    canRead,
    providerId,
    providerVersion,
    sessionId,
  });
  const dataScopeKey = JSON.stringify([
    sessionId,
    providerId,
    providerVersion,
    canRead,
    includeRetired,
  ]);
  const mutationScopeKey = JSON.stringify([
    dataScopeKey,
    canManage,
    allowWriteOnlyIssuer,
    prelinkIssuer ?? null,
  ]);
  const committedDataScopeRef = useRef(dataScopeKey);
  const committedMutationScopeRef = useRef(mutationScopeKey);
  const currentMutationScopeRef = useRef(mutationScopeKey);
  const listEpochRef = useRef(0);
  const paginationLockRef = useRef(false);
  const paginationAbortRef = useRef<AbortController | null>(null);
  const retirementAbortRef = useRef<AbortController | null>(null);
  const ledgerHeadingRef = useRef<HTMLHeadingElement | null>(null);
  const retirementHeadingRef = useRef<HTMLHeadingElement | null>(null);
  const retirementTriggerRef = useRef<HTMLButtonElement | null>(null);
  const prelinkIssuerInputRef = useRef<HTMLInputElement | null>(null);
  const prelinkFocusRestoreRef = useRef(false);
  const prelinkTriggerRef = useRef<HTMLButtonElement | null>(null);
  const prelinkUserInputRef = useRef<HTMLInputElement | null>(null);
  const prelinkReviewHeadingRef = useRef<HTMLHeadingElement | null>(null);
  const mutationLockRef = useRef<symbol | null>(null);
  const prelinkKeyRef = useRef<string | null>(null);
  const prelinkPayloadRef = useRef<string | null>(null);
  useLayoutEffect(() => {
    currentMutationScopeRef.current = mutationScopeKey;
    contextRef.current = {
      canManage,
      canRead,
      providerId,
      providerVersion,
      sessionId,
    };
  }, [
    canManage,
    canRead,
    mutationScopeKey,
    providerId,
    providerVersion,
    sessionId,
  ]);

  const resetPrelinkState = useCallback((): void => {
    prelinkFocusRestoreRef.current = false;
    prelinkKeyRef.current = null;
    prelinkPayloadRef.current = null;
    updateWorkspaceState({
      prelinkOpen: false,
      prelinkDraft: emptyPrelinkDraft,
      prelinkIssuerDraft: "",
      prelinkConfirmation: null,
      prelinkErrors: [],
    });
  }, []);

  const closePrelinkAndRestoreFocus = useCallback((): void => {
    resetPrelinkState();
    prelinkFocusRestoreRef.current = true;
  }, [resetPrelinkState]);

  const cancelRetirement = useCallback(
    (restoreFocus = false): void => {
      const trigger = retirementTriggerRef.current;
      retirementAbortRef.current?.abort();
      retirementAbortRef.current = null;
      retirementTriggerRef.current = null;
      setRetirement({ kind: "idle" });
      if (restoreFocus && trigger) {
        queueMicrotask(() => trigger.focus());
      }
    },
    [setRetirement],
  );

  const clearSensitiveAccountState = useCallback(
    (nextListState: AccountListState = { kind: "loading" }) => {
      listEpochRef.current += 1;
      paginationAbortRef.current?.abort();
      paginationAbortRef.current = null;
      paginationLockRef.current = false;
      mutationLockRef.current = null;
      updateWorkspaceState({
        listState: nextListState,
        loadingMore: false,
        paginationError: null,
      });
      resetPrelinkState();
      cancelRetirement();
      updateWorkspaceState({ mutationError: null, submitting: null });
      onMutationBusyChange(false);
    },
    [cancelRetirement, onMutationBusyChange, resetPrelinkState],
  );

  const handleAuthenticationError = useCallback(
    (caught: unknown, expectedSessionId: string): boolean => {
      if (!(caught instanceof PhaseTwoApiError) || caught.status !== 401) {
        return false;
      }
      if (contextRef.current.sessionId === expectedSessionId) {
        clearSensitiveAccountState();
        onUnauthenticated();
      }
      return true;
    },
    [clearSensitiveAccountState, onUnauthenticated],
  );

  const handleRequestError = useCallback(
    (
      caught: unknown,
      expectedProviderId: string,
      expectedSessionId: string,
    ) => {
      if (
        contextRef.current.providerId !== expectedProviderId ||
        contextRef.current.sessionId !== expectedSessionId ||
        !contextRef.current.canRead
      ) {
        return true;
      }
      if (caught instanceof PhaseTwoApiError && caught.status === 403) {
        clearSensitiveAccountState({
          kind: "error",
          message:
            "Account-register access was denied. Refresh the session before retrying; the API remains the authorization boundary.",
        });
        onPermissionError();
        return true;
      }
      return false;
    },
    [clearSensitiveAccountState, onPermissionError],
  );

  useEffect(() => {
    return () => {
      listEpochRef.current += 1;
      paginationAbortRef.current?.abort();
      retirementAbortRef.current?.abort();
      mutationLockRef.current = null;
      prelinkKeyRef.current = null;
      prelinkPayloadRef.current = null;
      onMutationBusyChange(false);
    };
  }, [onMutationBusyChange]);

  useEffect(() => {
    committedDataScopeRef.current = dataScopeKey;
    listEpochRef.current += 1;
    paginationAbortRef.current?.abort();
    paginationAbortRef.current = null;
    retirementAbortRef.current?.abort();
    retirementAbortRef.current = null;
    paginationLockRef.current = false;
    mutationLockRef.current = null;
    prelinkKeyRef.current = null;
    prelinkPayloadRef.current = null;
    updateWorkspaceState({
      listState: { kind: "loading" },
      loadingMore: false,
      paginationError: null,
    });
    resetPrelinkState();
    cancelRetirement();
    updateWorkspaceState({ mutationError: null, submitting: null });
    onMutationBusyChange(false);
  }, [cancelRetirement, dataScopeKey, onMutationBusyChange, resetPrelinkState]);

  useEffect(() => {
    committedMutationScopeRef.current = mutationScopeKey;
    mutationLockRef.current = null;
    resetPrelinkState();
    cancelRetirement();
    updateWorkspaceState({ mutationError: null, submitting: null });
    onMutationBusyChange(false);
  }, [
    cancelRetirement,
    mutationScopeKey,
    onMutationBusyChange,
    resetPrelinkState,
  ]);

  useEffect(() => {
    if (!canRead) {
      listEpochRef.current += 1;
      paginationAbortRef.current?.abort();
      paginationAbortRef.current = null;
      paginationLockRef.current = false;
      updateWorkspaceState({
        listState: { kind: "loading" },
        loadingMore: false,
        paginationError: null,
      });
      return undefined;
    }
    const controller = new AbortController();
    const expectedProviderId = providerId;
    const expectedSessionId = sessionId;
    const epoch = listEpochRef.current + 1;
    listEpochRef.current = epoch;
    paginationLockRef.current = true;
    updateWorkspaceState({
      loadingMore: true,
      paginationError: null,
      listState: { kind: "loading" },
    });
    void api
      .listPlatformAuthProviderAccounts(expectedProviderId, {
        includeRetired,
        signal: controller.signal,
      })
      .then((page) => {
        if (
          controller.signal.aborted ||
          listEpochRef.current !== epoch ||
          contextRef.current.providerId !== expectedProviderId ||
          contextRef.current.sessionId !== expectedSessionId
        ) {
          return;
        }
        setListState({
          items: page.items,
          kind: "ready",
          ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
        });
      })
      .catch((caught: unknown) => {
        if (
          handleAuthenticationError(caught, expectedSessionId) ||
          controller.signal.aborted ||
          isAbortError(caught) ||
          listEpochRef.current !== epoch ||
          handleRequestError(caught, expectedProviderId, expectedSessionId)
        ) {
          return;
        }
        setListState({
          kind: "error",
          message: describePhaseTwoError(
            caught,
            "The provider account register could not be loaded.",
          ),
        });
      })
      .finally(() => {
        if (
          listEpochRef.current === epoch &&
          contextRef.current.providerId === expectedProviderId &&
          contextRef.current.sessionId === expectedSessionId
        ) {
          paginationLockRef.current = false;
          setLoadingMore(false);
        }
      });
    return () => {
      controller.abort();
      if (listEpochRef.current === epoch) listEpochRef.current += 1;
    };
  }, [
    setListState,
    setLoadingMore,
    api,
    canRead,
    handleAuthenticationError,
    handleRequestError,
    includeRetired,
    listRevision,
    providerId,
    providerVersion,
    refreshRevision,
    sessionId,
  ]);

  useLayoutEffect(() => {
    if (retirement.kind === "ready") {
      retirementHeadingRef.current?.focus();
    }
  }, [retirement.kind]);

  useEffect(() => {
    if (prelinkConfirmation !== null) {
      prelinkReviewHeadingRef.current?.focus();
    }
  }, [prelinkConfirmation]);

  useEffect(() => {
    if (prelinkFocusRestoreRef.current && !prelinkOpen && submitting === null) {
      prelinkFocusRestoreRef.current = false;
      prelinkTriggerRef.current?.focus();
    }
  }, [prelinkOpen, submitting]);

  async function loadMore(): Promise<void> {
    if (
      committedDataScopeRef.current !== dataScopeKey ||
      listState.kind !== "ready" ||
      !listState.nextCursor ||
      paginationLockRef.current
    ) {
      return;
    }
    const cursor = listState.nextCursor;
    const expectedProviderId = providerId;
    const expectedSessionId = sessionId;
    const epoch = listEpochRef.current;
    const controller = new AbortController();
    paginationAbortRef.current?.abort();
    paginationAbortRef.current = controller;
    paginationLockRef.current = true;
    updateWorkspaceState({ loadingMore: true, paginationError: null });
    try {
      const page = await api.listPlatformAuthProviderAccounts(
        expectedProviderId,
        {
          after: cursor,
          includeRetired,
          signal: controller.signal,
        },
      );
      if (
        controller.signal.aborted ||
        listEpochRef.current !== epoch ||
        contextRef.current.providerId !== expectedProviderId ||
        contextRef.current.sessionId !== expectedSessionId
      ) {
        return;
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
        handleAuthenticationError(caught, expectedSessionId) ||
        controller.signal.aborted ||
        isAbortError(caught) ||
        listEpochRef.current !== epoch ||
        handleRequestError(caught, expectedProviderId, expectedSessionId)
      ) {
        return;
      }
      setPaginationError(
        describePhaseTwoError(
          caught,
          "More provider accounts could not be loaded.",
        ),
      );
    } finally {
      if (
        paginationAbortRef.current === controller &&
        listEpochRef.current === epoch
      ) {
        paginationAbortRef.current = null;
        paginationLockRef.current = false;
        // react-doctor-disable-next-line no-loading-flag-reset-outside-finally -- The owning request clears this flag in finally; the generation guard protects newer requests.
        setLoadingMore(false);
      }
    }
  }

  function updatePrelinkDraft(
    patch: Partial<PlatformIdentityAccountPrelinkDraft>,
  ): void {
    updateWorkspaceState({
      prelinkDraft: (current) => ({ ...current, ...patch }),
      prelinkConfirmation: null,
      prelinkErrors: [],
      mutationError: null,
    });
  }

  function updatePrelinkIssuer(value: string): void {
    updateWorkspaceState({
      prelinkIssuerDraft: value,
      prelinkConfirmation: null,
      prelinkErrors: [],
      mutationError: null,
    });
  }

  async function submitPrelink(event: React.FormEvent): Promise<void> {
    event.preventDefault();
    if (
      !canManage ||
      committedMutationScopeRef.current !== mutationScopeKey ||
      providerMutationBusy ||
      mutationLockRef.current !== null ||
      (prelinkIssuer === undefined && !allowWriteOnlyIssuer)
    ) {
      return;
    }
    const effectiveIssuer = prelinkIssuer ?? prelinkIssuerDraft;
    const errors = [
      ...validatePlatformIdentityAccountPrelinkDraft(prelinkDraft),
      ...validatePlatformIdentityAccountPrelinkIssuer(effectiveIssuer),
      ...(prelinkConfirmation === null
        ? []
        : validatePlatformIdentityAccountPrelinkConfirmation(
            prelinkDraft,
            prelinkConfirmation,
          )),
    ];
    setPrelinkErrors(errors);
    if (errors.length > 0) return;
    if (prelinkConfirmation === null) {
      setPrelinkConfirmation(emptyPrelinkConfirmation);
      return;
    }

    const payloadFingerprint = JSON.stringify([
      prelinkDraft.auditReason,
      effectiveIssuer,
      prelinkDraft.subject,
      prelinkDraft.userId,
    ]);
    let idempotencyKey =
      prelinkPayloadRef.current === payloadFingerprint
        ? prelinkKeyRef.current
        : null;
    if (idempotencyKey === null) {
      try {
        idempotencyKey = globalThis.crypto.randomUUID();
      } catch {
        setMutationError(
          "A secure idempotency key could not be generated. Reload this page before retrying.",
        );
        return;
      }
      prelinkKeyRef.current = idempotencyKey;
      prelinkPayloadRef.current = payloadFingerprint;
    }

    const lock = Symbol("platform-account-prelink");
    mutationLockRef.current = lock;
    updateWorkspaceState({ submitting: "prelink", mutationError: null });
    onMutationBusyChange(true);
    const expectedProviderId = providerId;
    const expectedSessionId = sessionId;
    const expectedMutationScopeKey = mutationScopeKey;
    try {
      const created = await api.prelinkPlatformAuthProviderAccount(
        csrfToken,
        expectedProviderId,
        idempotencyKey,
        prelinkDraft.auditReason,
        {
          issuer: effectiveIssuer,
          subject: prelinkDraft.subject,
          userId: prelinkDraft.userId,
        },
      );
      if (
        mutationLockRef.current !== lock ||
        currentMutationScopeRef.current !== expectedMutationScopeKey ||
        contextRef.current.providerId !== expectedProviderId ||
        contextRef.current.sessionId !== expectedSessionId ||
        !contextRef.current.canManage ||
        !contextRef.current.canRead
      ) {
        return;
      }
      onNotice({
        message:
          created.value.state === "active"
            ? `${created.value.user.displayName} is linked to this provider without changing platform authority.`
            : `${created.value.user.displayName} was already linked and later retired; the safe retry returned its current tombstone.`,
        tone: created.value.state === "active" ? "success" : "warning",
      });
      closePrelinkAndRestoreFocus();
      setListRevision((revision) => revision + 1);
    } catch (caught) {
      if (handleAuthenticationError(caught, expectedSessionId)) {
        return;
      }
      if (
        mutationLockRef.current === lock &&
        currentMutationScopeRef.current === expectedMutationScopeKey &&
        !handleRequestError(caught, expectedProviderId, expectedSessionId)
      ) {
        setMutationError(describePrelinkFailure(caught));
      }
    } finally {
      if (mutationLockRef.current === lock) {
        mutationLockRef.current = null;
        setSubmitting(null);
        onMutationBusyChange(false);
      }
    }
  }

  async function openRetirement(
    accountId: string,
    trigger?: HTMLButtonElement,
  ): Promise<void> {
    if (
      !canManage ||
      committedMutationScopeRef.current !== mutationScopeKey ||
      providerMutationBusy ||
      mutationLockRef.current !== null
    ) {
      return;
    }
    if (trigger) retirementTriggerRef.current = trigger;
    resetPrelinkState();
    retirementAbortRef.current?.abort();
    const controller = new AbortController();
    retirementAbortRef.current = controller;
    const expectedProviderId = providerId;
    const expectedSessionId = sessionId;
    const expectedMutationScopeKey = mutationScopeKey;
    updateWorkspaceState({
      mutationError: null,
      retirement: { accountId, kind: "loading" },
    });
    try {
      const current = await api.getPlatformAuthProviderAccount(
        expectedProviderId,
        accountId,
        controller.signal,
      );
      if (
        controller.signal.aborted ||
        currentMutationScopeRef.current !== expectedMutationScopeKey ||
        contextRef.current.providerId !== expectedProviderId ||
        contextRef.current.sessionId !== expectedSessionId ||
        !contextRef.current.canManage ||
        !contextRef.current.canRead
      ) {
        return;
      }
      if (current.value.state === "retired") {
        onNotice({
          message: `${current.value.user.displayName} is already retired. The register has been refreshed.`,
          tone: "warning",
        });
        updateWorkspaceState({
          retirement: { kind: "idle" },
          listRevision: (revision) => revision + 1,
        });
        queueMicrotask(() => ledgerHeadingRef.current?.focus());
        return;
      }
      setRetirement({
        confirmation: "",
        current,
        errors: [],
        kind: "ready",
        reason: "",
      });
    } catch (caught) {
      if (
        handleAuthenticationError(caught, expectedSessionId) ||
        controller.signal.aborted ||
        isAbortError(caught) ||
        currentMutationScopeRef.current !== expectedMutationScopeKey ||
        handleRequestError(caught, expectedProviderId, expectedSessionId)
      ) {
        return;
      }
      setRetirement({
        accountId,
        kind: "error",
        message: describePhaseTwoError(
          caught,
          "The current provider account version could not be loaded.",
        ),
      });
    } finally {
      if (retirementAbortRef.current === controller) {
        retirementAbortRef.current = null;
      }
    }
  }

  async function submitRetirement(event: React.FormEvent): Promise<void> {
    event.preventDefault();
    if (
      retirement.kind !== "ready" ||
      !canManage ||
      committedMutationScopeRef.current !== mutationScopeKey ||
      providerMutationBusy ||
      mutationLockRef.current !== null
    ) {
      return;
    }
    const errors = validatePlatformIdentityAccountRetirement(
      retirement.current.value.id,
      retirement.confirmation,
      retirement.reason,
    );
    setRetirement({ ...retirement, errors });
    if (errors.length > 0) return;

    const lock = Symbol("platform-account-retire");
    mutationLockRef.current = lock;
    updateWorkspaceState({ submitting: "retire", mutationError: null });
    onMutationBusyChange(true);
    const expectedProviderId = providerId;
    const expectedSessionId = sessionId;
    const expectedMutationScopeKey = mutationScopeKey;
    try {
      const retired = await api.retirePlatformAuthProviderAccount(
        csrfToken,
        expectedProviderId,
        retirement.current.value.id,
        retirement.current,
        retirement.reason,
      );
      if (
        mutationLockRef.current !== lock ||
        currentMutationScopeRef.current !== expectedMutationScopeKey ||
        contextRef.current.providerId !== expectedProviderId ||
        contextRef.current.sessionId !== expectedSessionId ||
        !contextRef.current.canManage ||
        !contextRef.current.canRead
      ) {
        return;
      }
      onNotice({
        message: `${retired.value.user.displayName} was retired. Linked admission grants, continuations, and session families were revoked by the server.`,
        tone: "success",
      });
      updateWorkspaceState({
        retirement: { kind: "idle" },
        listRevision: (revision) => revision + 1,
      });
      queueMicrotask(() => ledgerHeadingRef.current?.focus());
    } catch (caught) {
      if (handleAuthenticationError(caught, expectedSessionId)) {
        return;
      }
      if (
        mutationLockRef.current === lock &&
        currentMutationScopeRef.current === expectedMutationScopeKey &&
        !handleRequestError(caught, expectedProviderId, expectedSessionId)
      ) {
        const stale =
          caught instanceof PhaseTwoApiError &&
          (caught.status === 409 || caught.status === 412);
        setMutationError(
          stale
            ? "The account changed or was already retired. Refresh the register before retrying."
            : describePhaseTwoError(
                caught,
                "The provider account could not be retired.",
              ),
        );
        if (stale) {
          updateWorkspaceState({
            retirement: { kind: "idle" },
            listRevision: (revision) => revision + 1,
          });
        }
      }
    } finally {
      if (mutationLockRef.current === lock) {
        mutationLockRef.current = null;
        setSubmitting(null);
        onMutationBusyChange(false);
      }
    }
  }

  const prelinkAvailable = prelinkIssuer !== undefined || allowWriteOnlyIssuer;
  const dataScopeIsCurrent = committedDataScopeRef.current === dataScopeKey;
  const mutationScopeIsCurrent =
    committedMutationScopeRef.current === mutationScopeKey;
  const visibleListState: AccountListState = dataScopeIsCurrent
    ? listState
    : { kind: "loading" };
  const visibleRetirement: RetirementState = mutationScopeIsCurrent
    ? retirement
    : { kind: "idle" };
  const visiblePrelinkOpen = mutationScopeIsCurrent && canManage && prelinkOpen;
  const controlsDisabled =
    !mutationScopeIsCurrent || providerMutationBusy || submitting !== null;
  const selectedRetirementAccountId =
    visibleRetirement.kind === "idle"
      ? null
      : visibleRetirement.kind === "ready"
        ? visibleRetirement.current.value.id
        : visibleRetirement.accountId;

  return {
    kind: "ready" as const,
    data: {
      canManage,
      canRead,
      cancelRetirement,
      closePrelinkAndRestoreFocus,
      controlsDisabled,
      dataScopeIsCurrent,
      includeRetired,
      ledgerHeadingRef,
      loadMore,
      loadingMore,
      mutationError,
      mutationScopeIsCurrent,
      openRetirement,
      paginationError,
      prelinkAvailable,
      prelinkConfirmation,
      prelinkDraft,
      prelinkErrors,
      prelinkIssuer,
      prelinkIssuerDraft,
      prelinkIssuerInputRef,
      prelinkRegionId,
      prelinkReviewHeadingRef,
      prelinkReviewTitleId,
      prelinkTitleId,
      prelinkTriggerRef,
      prelinkUserInputRef,
      resetPrelinkState,
      retirementHeadingRef,
      retirementRegionId,
      retirementTitleId,
      selectedRetirementAccountId,
      setIncludeRetired,
      setListRevision,
      setMutationError,
      setPrelinkConfirmation,
      setPrelinkErrors,
      setPrelinkOpen,
      setRetirement,
      submitPrelink,
      submitRetirement,
      submitting,
      titleId,
      updatePrelinkDraft,
      updatePrelinkIssuer,
      visibleListState,
      visiblePrelinkOpen,
      visibleRetirement,
    },
  };
}

function PlatformAuthProviderAccountsView({
  model,
}: {
  model: Extract<
    ReturnType<typeof usePlatformAuthProviderAccountsModel>,
    { kind: "ready" }
  >["data"];
}): React.JSX.Element {
  const {
    canRead,
    dataScopeIsCurrent,
    mutationError,
    mutationScopeIsCurrent,
    paginationError,
    titleId,
  } = model;
  return (
    <section className="platform-idp-accounts" aria-labelledby={titleId}>
      <AccountInventoryHeading model={model} />
      <p className="platform-idp-accounts__intro">
        Inspect safe user links and admission revisions. Issuers, subjects,
        aliases, claims, credentials, roles, memberships, and session evidence
        are never returned by this register.
      </p>

      {!canRead ? (
        <Alert>
          <ShieldAlert aria-hidden="true" />
          <AlertTitle>Account register permission not returned</AlertTitle>
          <AlertDescription>
            Platform provider visibility does not grant identity-account read
            authority.
          </AlertDescription>
        </Alert>
      ) : (
        <>
          <AccountInventoryToolbar model={model} />

          {<AccountPrelinkForm model={model} />}

          {mutationScopeIsCurrent && mutationError ? (
            <FocusedError message={mutationError} />
          ) : null}
          {<AccountInventoryLoading model={model} />}
          {<AccountInventoryError model={model} />}
          {<AccountInventoryEmpty model={model} />}
          {<AccountInventory model={model} />}
          {dataScopeIsCurrent && paginationError ? (
            <FocusedError autoFocus={false} message={paginationError} />
          ) : null}
          {<AccountInventoryPagination model={model} />}

          <AccountRetirementPanel model={model} />
        </>
      )}
    </section>
  );
}

function ValidationAlert({
  errors,
}: {
  errors: readonly string[];
}): React.JSX.Element | null {
  if (errors.length === 0) return null;
  return (
    <FormValidationAlert errors={errors} title="Review the account action" />
  );
}

function formatInstant(value: string): string {
  const instant = new Date(value);
  return Number.isNaN(instant.valueOf())
    ? value
    : dateTimeFormatter.format(instant);
}

function describePrelinkFailure(caught: unknown): string {
  if (caught instanceof PhaseTwoApiError && caught.status === 409) {
    return "The prelink request conflicts with current provider, identity, or user state. Reload the register before retrying.";
  }
  return "The provider account could not be prelinked. Verify the write-only issuer and subject, target user, and current provider state.";
}

function isAbortError(caught: unknown): boolean {
  return caught instanceof DOMException && caught.name === "AbortError";
}

function AccountPrelinkForm({
  model,
}: {
  model: React.ComponentProps<typeof PlatformAuthProviderAccountsView>["model"];
}): React.ReactNode {
  const {
    controlsDisabled,
    prelinkAvailable,
    prelinkConfirmation,
    prelinkDraft,
    prelinkErrors,
    prelinkRegionId,
    prelinkTitleId,
    submitPrelink,
    updatePrelinkDraft,
    visiblePrelinkOpen,
  } = model;
  return visiblePrelinkOpen && prelinkAvailable ? (
    <form
      id={prelinkRegionId}
      className="platform-idp-account-form"
      aria-labelledby={prelinkTitleId}
      onSubmit={(event) => void submitPrelink(event)}
    >
      <div>
        <h4 id={prelinkTitleId}>Prelink exact OIDC identity</h4>
        <p>
          This creates no role, permission, membership, or tenant admission. The
          exact subject is protected before persistence and is never reflected.
        </p>
      </div>
      {<AccountPrelinkIssuer model={model} />}
      <AccountPrelinkTargetFields model={model} />
      <FormField
        htmlFor={`${prelinkTitleId}-reason`}
        label="Audit reason"
        hint="Visible ASCII without commas. Never include the subject, claims, secrets, or customer data."
      >
        <Textarea
          aria-describedby={`${prelinkTitleId}-reason-hint`}
          id={`${prelinkTitleId}-reason`}
          disabled={controlsDisabled || prelinkConfirmation !== null}
          value={prelinkDraft.auditReason}
          onChange={(event) =>
            updatePrelinkDraft({
              auditReason: event.currentTarget.value,
            })
          }
        />
      </FormField>
      <Alert variant="destructive">
        <ShieldAlert aria-hidden="true" />
        <AlertTitle>Permanent subject reservation</AlertTitle>
        <AlertDescription>
          A wrong user ID can redirect future authentication to the wrong
          platform account. This exact issuer and case-sensitive subject remain
          reserved even after retirement and cannot be reassigned. Verify both
          values against the identity provider before continuing.
        </AlertDescription>
      </Alert>
      {<AccountPrelinkConfirmation model={model} />}
      <ValidationAlert errors={prelinkErrors} />
      <AccountPrelinkActions model={model} />
    </form>
  ) : null;
}

function AccountInventory({
  model,
}: {
  model: React.ComponentProps<typeof PlatformAuthProviderAccountsView>["model"];
}): React.ReactNode {
  const { visibleListState } = model;
  return visibleListState.kind === "ready" &&
    visibleListState.items.length > 0 ? (
    <AccountInventoryTable model={model} />
  ) : null;
}

function AccountRetirementPanel({
  model,
}: {
  model: React.ComponentProps<typeof PlatformAuthProviderAccountsView>["model"];
}): React.ReactNode {
  const { openRetirement, retirementRegionId, visibleRetirement } = model;
  return (
    <div id={retirementRegionId} aria-live="polite">
      {visibleRetirement.kind === "loading" ? (
        <Alert>
          <RefreshCw aria-hidden="true" />
          <AlertTitle>Loading current account version</AlertTitle>
          <AlertDescription>
            Retirement remains locked until the server returns a current strong
            ETag.
          </AlertDescription>
        </Alert>
      ) : null}
      {visibleRetirement.kind === "error" ? (
        <div className="platform-idp-load-error">
          <FocusedError message={visibleRetirement.message} />
          <Button
            type="button"
            variant="outline"
            onClick={() => void openRetirement(visibleRetirement.accountId)}
          >
            <RefreshCw aria-hidden="true" /> Reload current account
          </Button>
        </div>
      ) : null}
      {<AccountRetirementForm model={model} />}
    </div>
  );
}

interface PlatformAuthProviderAccountsState {
  includeRetired: boolean;
  listState: AccountListState;
  listRevision: number;
  loadingMore: boolean;
  paginationError: string | null;
  prelinkOpen: boolean;
  prelinkDraft: PlatformIdentityAccountPrelinkDraft;
  prelinkIssuerDraft: string;
  prelinkConfirmation: PlatformIdentityAccountPrelinkConfirmation | null;
  prelinkErrors: readonly string[];
  retirement: RetirementState;
  mutationError: string | null;
  submitting: "prelink" | "retire" | null;
}

function AccountInventoryToolbar({
  model,
}: {
  model: React.ComponentProps<typeof PlatformAuthProviderAccountsView>["model"];
}): React.ReactNode {
  const {
    canManage,
    cancelRetirement,
    controlsDisabled,
    includeRetired,
    prelinkAvailable,
    prelinkRegionId,
    prelinkTriggerRef,
    resetPrelinkState,
    setIncludeRetired,
    setMutationError,
    setPrelinkOpen,
    visiblePrelinkOpen,
  } = model;
  return (
    <div className="platform-idp-account-toolbar">
      <label className="platform-idp-account-retired-filter">
        <Checkbox
          checked={includeRetired}
          disabled={controlsDisabled}
          onCheckedChange={(checked) => {
            setIncludeRetired(checked === true);
            cancelRetirement();
          }}
        />
        <span>Include retired tombstones</span>
      </label>
      {canManage && prelinkAvailable ? (
        <Button
          ref={prelinkTriggerRef}
          type="button"
          size="sm"
          variant="outline"
          disabled={controlsDisabled}
          aria-controls={prelinkRegionId}
          aria-expanded={visiblePrelinkOpen}
          onClick={() => {
            cancelRetirement();
            setMutationError(null);
            if (visiblePrelinkOpen) {
              resetPrelinkState();
            } else {
              resetPrelinkState();
              setPrelinkOpen(true);
            }
          }}
        >
          <Link2 aria-hidden="true" /> Prelink account
        </Button>
      ) : canManage ? (
        <Badge variant="secondary">
          Prelink requires a configured, unarchived OIDC provider
        </Badge>
      ) : (
        <Badge variant="outline">
          <ShieldCheck aria-hidden="true" /> Read-only authority
        </Badge>
      )}
    </div>
  );
}

function AccountPrelinkIssuer({
  model,
}: {
  model: React.ComponentProps<typeof AccountPrelinkForm>["model"];
}): React.ReactNode {
  const {
    controlsDisabled,
    prelinkConfirmation,
    prelinkIssuer,
    prelinkIssuerDraft,
    prelinkIssuerInputRef,
    prelinkTitleId,
    updatePrelinkIssuer,
  } = model;
  return prelinkIssuer === undefined ? (
    <FormField
      htmlFor={`${prelinkTitleId}-issuer`}
      label="Exact OIDC issuer"
      hint="Write-only canonical HTTPS issuer. Provider configuration and lifecycle are revalidated by the server."
    >
      <Input
        ref={prelinkIssuerInputRef}
        aria-describedby={`${prelinkTitleId}-issuer-hint`}
        id={`${prelinkTitleId}-issuer`}
        autoComplete="off"
        disabled={controlsDisabled || prelinkConfirmation !== null}
        spellCheck={false}
        type="url"
        value={prelinkIssuerDraft}
        onChange={(event) => updatePrelinkIssuer(event.currentTarget.value)}
      />
    </FormField>
  ) : (
    <dl className="platform-idp-account-issuer">
      <div>
        <dt>Issuer fixed by provider</dt>
        <dd>
          <code>{prelinkIssuer}</code>
        </dd>
      </div>
    </dl>
  );
}

function AccountPrelinkTargetFields({
  model,
}: {
  model: React.ComponentProps<typeof AccountPrelinkForm>["model"];
}): React.ReactNode {
  const {
    controlsDisabled,
    prelinkConfirmation,
    prelinkDraft,
    prelinkTitleId,
    prelinkUserInputRef,
    updatePrelinkDraft,
  } = model;
  return (
    <div className="platform-idp-account-form-grid">
      <FormField
        htmlFor={`${prelinkTitleId}-user`}
        label="Existing platform user ID"
        hint="Exact UUIDv7 only; the link does not grant platform authority."
      >
        <Input
          ref={prelinkUserInputRef}
          aria-describedby={`${prelinkTitleId}-user-hint`}
          id={`${prelinkTitleId}-user`}
          autoComplete="off"
          disabled={controlsDisabled || prelinkConfirmation !== null}
          value={prelinkDraft.userId}
          onChange={(event) =>
            updatePrelinkDraft({ userId: event.currentTarget.value })
          }
        />
      </FormField>
      <FormField
        htmlFor={`${prelinkTitleId}-subject`}
        label="Exact OIDC subject"
        hint="Case-sensitive and write-only. Spaces are preserved exactly."
      >
        <Input
          aria-describedby={`${prelinkTitleId}-subject-hint`}
          id={`${prelinkTitleId}-subject`}
          autoComplete="off"
          disabled={controlsDisabled || prelinkConfirmation !== null}
          spellCheck={false}
          type="password"
          value={prelinkDraft.subject}
          onChange={(event) =>
            updatePrelinkDraft({ subject: event.currentTarget.value })
          }
        />
      </FormField>
    </div>
  );
}

function AccountPrelinkConfirmation({
  model,
}: {
  model: React.ComponentProps<typeof AccountPrelinkForm>["model"];
}): React.ReactNode {
  const {
    controlsDisabled,
    prelinkConfirmation,
    prelinkReviewHeadingRef,
    prelinkReviewTitleId,
    prelinkTitleId,
    setPrelinkConfirmation,
    setPrelinkErrors,
  } = model;
  return prelinkConfirmation === null ? null : (
    <div role="group" aria-labelledby={prelinkReviewTitleId}>
      <h5 id={prelinkReviewTitleId} ref={prelinkReviewHeadingRef} tabIndex={-1}>
        Confirm permanent authentication mapping
      </h5>
      <div className="platform-idp-account-form-grid">
        <FormField
          htmlFor={`${prelinkTitleId}-confirm-user`}
          label="Confirm platform user ID"
          hint="Re-enter the exact UUIDv7 authentication target."
        >
          <Input
            aria-describedby={`${prelinkTitleId}-confirm-user-hint`}
            id={`${prelinkTitleId}-confirm-user`}
            autoComplete="off"
            disabled={controlsDisabled}
            value={prelinkConfirmation.userId}
            onChange={(event) => {
              setPrelinkConfirmation({
                ...prelinkConfirmation,
                userId: event.currentTarget.value,
              });
              setPrelinkErrors([]);
            }}
          />
        </FormField>
        <FormField
          htmlFor={`${prelinkTitleId}-confirm-subject`}
          label="Re-enter exact OIDC subject"
          hint="Case and whitespace must match the first entry exactly."
        >
          <Input
            aria-describedby={`${prelinkTitleId}-confirm-subject-hint`}
            id={`${prelinkTitleId}-confirm-subject`}
            autoComplete="off"
            disabled={controlsDisabled}
            spellCheck={false}
            type="password"
            value={prelinkConfirmation.subject}
            onChange={(event) => {
              setPrelinkConfirmation({
                ...prelinkConfirmation,
                subject: event.currentTarget.value,
              });
              setPrelinkErrors([]);
            }}
          />
        </FormField>
      </div>
    </div>
  );
}

function AccountPrelinkActions({
  model,
}: {
  model: React.ComponentProps<typeof AccountPrelinkForm>["model"];
}): React.ReactNode {
  const {
    closePrelinkAndRestoreFocus,
    controlsDisabled,
    prelinkConfirmation,
    prelinkIssuer,
    prelinkIssuerInputRef,
    prelinkUserInputRef,
    setMutationError,
    setPrelinkConfirmation,
    setPrelinkErrors,
    submitting,
  } = model;
  return (
    <div className="platform-idp-form-actions">
      <Button
        type="button"
        variant="outline"
        disabled={controlsDisabled}
        onClick={() => {
          closePrelinkAndRestoreFocus();
          setMutationError(null);
        }}
      >
        Cancel
      </Button>
      {prelinkConfirmation === null ? null : (
        <Button
          type="button"
          variant="outline"
          disabled={controlsDisabled}
          onClick={() => {
            setPrelinkConfirmation(null);
            setPrelinkErrors([]);
            setMutationError(null);
            queueMicrotask(() =>
              (prelinkIssuer === undefined
                ? prelinkIssuerInputRef.current
                : prelinkUserInputRef.current
              )?.focus(),
            );
          }}
        >
          Back to edit
        </Button>
      )}
      <Button type="submit" disabled={controlsDisabled}>
        <Link2 aria-hidden="true" />
        {submitting === "prelink"
          ? "Prelinking…"
          : prelinkConfirmation === null
            ? "Review permanent link"
            : "Confirm permanent link"}
      </Button>
    </div>
  );
}

function AccountInventoryTable({
  model,
}: {
  model: React.ComponentProps<typeof AccountInventory>["model"];
}): React.ReactNode {
  const {
    canManage,
    cancelRetirement,
    controlsDisabled,
    openRetirement,
    retirementRegionId,
    selectedRetirementAccountId,
    setMutationError,
    visibleListState,
  } = model;
  if (visibleListState.kind !== "ready") return null;
  return (
    <div className="platform-idp-table-wrap">
      <Table className="platform-idp-account-table">
        <TableCaption>
          Safe account links ordered by immutable account ID.
        </TableCaption>
        <TableColumnHeaders
          columns={[
            "Platform user",
            "State",
            "Admission pins",
            "Last observed",
          ]}
          actionLabel="Action"
          actionPresentation="visible"
        />
        <TableBody>
          {visibleListState.items.map((account) => (
            <TableRow key={account.id}>
              <TableCell>
                <div className="platform-idp-account-person">
                  <strong>{account.user.displayName}</strong>
                  <span>{account.user.email ?? "No profile email"}</span>
                  <code>{account.id}</code>
                </div>
              </TableCell>
              <TableCell>
                {account.state === "active" ? (
                  <Badge>
                    <ShieldCheck aria-hidden="true" /> Active
                  </Badge>
                ) : (
                  <Badge variant="outline">
                    <UserRoundX aria-hidden="true" /> Retired
                  </Badge>
                )}
                {!account.user.active ? (
                  <small className="platform-idp-account-user-state">
                    Platform user disabled
                  </small>
                ) : null}
              </TableCell>
              <TableCell>
                <code>
                  cfg {account.admittedConfigurationRevision} · sec{" "}
                  {account.admittedSecurityRevision}
                </code>
              </TableCell>
              <TableCell>
                {account.lastObservationState === "legacy_unknown" ? (
                  <span>Legacy observation unavailable</span>
                ) : account.lastObservedAt === null ? (
                  <span>Observation unavailable</span>
                ) : (
                  <time dateTime={account.lastObservedAt}>
                    {formatInstant(account.lastObservedAt)}
                  </time>
                )}
              </TableCell>
              <TableCell className="text-right">
                {canManage && account.state === "active" ? (
                  <Button
                    type="button"
                    size="sm"
                    variant="outline"
                    disabled={controlsDisabled}
                    aria-controls={retirementRegionId}
                    aria-expanded={selectedRetirementAccountId === account.id}
                    aria-label={`Retire account link ${account.id} for ${account.user.displayName}`}
                    onClick={(event) => {
                      if (selectedRetirementAccountId === account.id) {
                        cancelRetirement();
                        setMutationError(null);
                        return;
                      }
                      void openRetirement(account.id, event.currentTarget);
                    }}
                  >
                    Retire
                  </Button>
                ) : (
                  <span aria-hidden="true">—</span>
                )}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}

function AccountRetirementForm({
  model,
}: {
  model: React.ComponentProps<typeof AccountRetirementPanel>["model"];
}): React.ReactNode {
  const {
    cancelRetirement,
    controlsDisabled,
    retirementHeadingRef,
    retirementTitleId,
    setMutationError,
    setRetirement,
    submitRetirement,
    submitting,
    titleId,
    visibleRetirement,
  } = model;
  return visibleRetirement.kind === "ready" ? (
    <form
      aria-labelledby={retirementTitleId}
      className="platform-idp-account-form platform-idp-account-form--retire"
      onSubmit={(event) => void submitRetirement(event)}
    >
      <div>
        <h4 id={retirementTitleId} ref={retirementHeadingRef} tabIndex={-1}>
          Retire account link
        </h4>
        <p>
          Retirement is irreversible. The server retains the protected subject
          reservation and revokes linked grants, continuations, profile
          contributions, and complete session families.
        </p>
      </div>
      <div className="platform-idp-account-retire-target">
        <UserRoundX aria-hidden="true" />
        <span>
          <strong>{visibleRetirement.current.value.user.displayName}</strong>
          <code>{visibleRetirement.current.value.id}</code>
        </span>
      </div>
      <FormField
        htmlFor={`${titleId}-retire-confirmation`}
        label="Confirm account ID"
        hint="Enter the exact account ID shown above."
      >
        <Input
          aria-describedby={`${titleId}-retire-confirmation-hint`}
          id={`${titleId}-retire-confirmation`}
          autoComplete="off"
          disabled={controlsDisabled}
          value={visibleRetirement.confirmation}
          onChange={(event) =>
            setRetirement({
              ...visibleRetirement,
              confirmation: event.currentTarget.value,
              errors: [],
            })
          }
        />
      </FormField>
      <FormField
        htmlFor={`${titleId}-retire-reason`}
        label="Audit reason"
        hint="Visible ASCII without commas. Never include subjects, claims, secrets, or customer data."
      >
        <Textarea
          aria-describedby={`${titleId}-retire-reason-hint`}
          id={`${titleId}-retire-reason`}
          disabled={controlsDisabled}
          value={visibleRetirement.reason}
          onChange={(event) =>
            setRetirement({
              ...visibleRetirement,
              errors: [],
              reason: event.currentTarget.value,
            })
          }
        />
      </FormField>
      <ValidationAlert errors={visibleRetirement.errors} />
      <div className="platform-idp-form-actions">
        <Button
          type="button"
          variant="outline"
          disabled={controlsDisabled}
          onClick={() => {
            cancelRetirement(true);
            setMutationError(null);
          }}
        >
          Cancel
        </Button>
        <Button type="submit" variant="destructive" disabled={controlsDisabled}>
          <UserRoundX aria-hidden="true" />
          {submitting === "retire" ? "Retiring…" : "Retire account"}
        </Button>
      </div>
    </form>
  ) : null;
}

function AccountInventoryHeading({
  model,
}: {
  model: React.ComponentProps<typeof PlatformAuthProviderAccountsView>["model"];
}): React.ReactNode {
  const { ledgerHeadingRef, titleId, visibleListState } = model;
  return (
    <div className="platform-idp-section-heading">
      <div>
        <p className="section-label">Provider-global trust ledger</p>
        <h3 id={titleId} ref={ledgerHeadingRef} tabIndex={-1}>
          Linked platform accounts
        </h3>
      </div>
      {visibleListState.kind === "ready" ? (
        <Badge variant="outline">
          <Fingerprint aria-hidden="true" /> {visibleListState.items.length}{" "}
          loaded
        </Badge>
      ) : null}
    </div>
  );
}

function AccountInventoryLoading({
  model,
}: {
  model: React.ComponentProps<typeof PlatformAuthProviderAccountsView>["model"];
}): React.ReactNode {
  const { visibleListState } = model;
  return visibleListState.kind === "loading" ? (
    <div
      className="platform-idp-skeleton-grid"
      aria-busy="true"
      aria-label="Loading linked platform accounts"
    >
      <div className="skeleton-line skeleton-line--title" />
      <div className="skeleton-line" />
      <div className="skeleton-line" />
    </div>
  ) : null;
}

function AccountInventoryError({
  model,
}: {
  model: React.ComponentProps<typeof PlatformAuthProviderAccountsView>["model"];
}): React.ReactNode {
  const { setListRevision, visibleListState } = model;
  return visibleListState.kind === "error" ? (
    <div className="platform-idp-load-error">
      <FocusedError message={visibleListState.message} />
      <Button
        type="button"
        variant="outline"
        onClick={() => setListRevision((revision) => revision + 1)}
      >
        <RefreshCw aria-hidden="true" /> Reload account register
      </Button>
    </div>
  ) : null;
}

function AccountInventoryEmpty({
  model,
}: {
  model: React.ComponentProps<typeof PlatformAuthProviderAccountsView>["model"];
}): React.ReactNode {
  const { includeRetired, visibleListState } = model;
  return visibleListState.kind === "ready" &&
    visibleListState.items.length === 0 ? (
    <div className="platform-idp-account-empty">
      <Fingerprint aria-hidden="true" />
      <div>
        <strong>No account links in this view</strong>
        <p>
          {includeRetired
            ? "Prelink an exact OIDC subject to an existing platform user."
            : "Include retired tombstones or prelink an active OIDC account."}
        </p>
      </div>
    </div>
  ) : null;
}

function AccountInventoryPagination({
  model,
}: {
  model: React.ComponentProps<typeof PlatformAuthProviderAccountsView>["model"];
}): React.ReactNode {
  const { controlsDisabled, loadMore, loadingMore, visibleListState } = model;
  return visibleListState.kind === "ready" && visibleListState.nextCursor ? (
    <div className="platform-idp-pagination">
      <Button
        type="button"
        variant="outline"
        disabled={loadingMore || controlsDisabled}
        onClick={() => void loadMore()}
      >
        {loadingMore ? "Loading…" : "Load more accounts"}
      </Button>
    </div>
  ) : null;
}
