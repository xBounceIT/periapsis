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
import { Checkbox } from "@periapsis/ui/components/ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@periapsis/ui/components/ui/dialog";
import { Input } from "@periapsis/ui/components/ui/input";
import { Label } from "@periapsis/ui/components/ui/label";
import {
  Table,
  TableBody,
  TableCaption,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@periapsis/ui/components/ui/table";
import {
  CircleAlert,
  KeyRound,
  Plus,
  RefreshCw,
  ShieldCheck,
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
import { reduceWorkspaceState } from "./workspace-state";

import { useSession } from "../auth/session-context";
import { FocusedError } from "../components/focused-error";
import { FormField } from "../components/form-field";
import {
  describePhaseTwoError,
  hasPermission,
  PhaseTwoApiError,
  platformIdentityAccountManagePermission,
  platformIdentityAccountReadPermission,
  type PlatformLocalAccountInvitationView,
  type PlatformLocalAccountMutationView,
  type PlatformLocalAccountView,
  type VersionedView,
} from "../lib/phase-two-types";
import { platformUtf8ByteLength } from "../lib/platform-auth-provider-validation";

type AccountListState =
  | { kind: "error"; message: string }
  | {
      items: readonly PlatformLocalAccountView[];
      kind: "ready";
      nextCursor?: string;
    }
  | { kind: "loading" };

type DetailState =
  | { kind: "error"; message: string }
  | { kind: "loading" }
  | { kind: "ready"; resource: VersionedView<PlatformLocalAccountView> };

interface CeremonyNotice {
  accountLabel: string;
  kind: "invitation" | "recovery";
  provisioningUri: string;
  secret: string;
  sessionId: string;
  token: string;
}

const auditReasonPattern =
  /^[\x21-\x2B\x2D-\x7E](?:[\x20-\x2B\x2D-\x7E]*[\x21-\x2B\x2D-\x7E])?$/;
const ceremonyTokenPattern = /^(?!A{43}$)[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/;

export function PlatformLocalAccountsPage(): React.JSX.Element {
  const model = usePlatformLocalAccountsPageModel();
  if (model.kind === "content") return model.content;
  return <PlatformLocalAccountsPageView model={model.data} />;
}

function usePlatformLocalAccountsPageModel() {
  const { api, clearSession, session } = useSession();
  const canRead = hasPermission(session, platformIdentityAccountReadPermission);
  const canManage =
    canRead && hasPermission(session, platformIdentityAccountManagePermission);
  const [workspaceState, updateWorkspaceState] = useReducer(
    reduceWorkspaceState<PlatformLocalAccountsPageState>,
    undefined,
    (): PlatformLocalAccountsPageState => ({
      includeDisabled: true,
      listState: {
        kind: "loading",
      },
      revision: 0,
      loadingMore: false,
      listPageError: null,
      inviteOpen: false,
      selectedAccountId: null,
      detailState: {
        kind: "loading",
      },
      notice: null,
    }),
  );
  const {
    includeDisabled,
    listState,
    revision,
    loadingMore,
    listPageError,
    inviteOpen,
    selectedAccountId,
    detailState,
    notice,
  } = workspaceState;
  const {
    setIncludeDisabled,
    setListState,
    setRevision,
    setLoadingMore,
    setListPageError,
    setInviteOpen,
    setDetailState,
    setNotice,
  } = useMemo(
    () => ({
      setIncludeDisabled: (
        value: React.SetStateAction<
          PlatformLocalAccountsPageState["includeDisabled"]
        >,
      ) => updateWorkspaceState({ includeDisabled: value }),
      setListState: (
        value: React.SetStateAction<
          PlatformLocalAccountsPageState["listState"]
        >,
      ) => updateWorkspaceState({ listState: value }),
      setRevision: (
        value: React.SetStateAction<PlatformLocalAccountsPageState["revision"]>,
      ) => updateWorkspaceState({ revision: value }),
      setLoadingMore: (
        value: React.SetStateAction<
          PlatformLocalAccountsPageState["loadingMore"]
        >,
      ) => updateWorkspaceState({ loadingMore: value }),
      setListPageError: (
        value: React.SetStateAction<
          PlatformLocalAccountsPageState["listPageError"]
        >,
      ) => updateWorkspaceState({ listPageError: value }),
      setInviteOpen: (
        value: React.SetStateAction<
          PlatformLocalAccountsPageState["inviteOpen"]
        >,
      ) => updateWorkspaceState({ inviteOpen: value }),
      setDetailState: (
        value: React.SetStateAction<
          PlatformLocalAccountsPageState["detailState"]
        >,
      ) => updateWorkspaceState({ detailState: value }),
      setNotice: (
        value: React.SetStateAction<PlatformLocalAccountsPageState["notice"]>,
      ) => updateWorkspaceState({ notice: value }),
    }),
    [updateWorkspaceState],
  );

  const sessionIdRef = useRef(session.id);
  const listEpochRef = useRef(0);
  const detailEpochRef = useRef(0);
  useLayoutEffect(() => {
    sessionIdRef.current = session.id;
  }, [session]);
  const visibleNotice = notice?.sessionId === session.id ? notice : null;

  const handleError = useCallback(
    (caught: unknown, fallback: string, expectedSessionId: string): string => {
      if (
        caught instanceof PhaseTwoApiError &&
        caught.status === 401 &&
        sessionIdRef.current === expectedSessionId
      ) {
        clearSession(expectedSessionId);
      }
      return describePhaseTwoError(caught, fallback);
    },
    [clearSession],
  );

  useEffect(() => {
    updateWorkspaceState({
      inviteOpen: false,
      selectedAccountId: null,
      detailState: { kind: "loading" },
      notice: null,
      loadingMore: false,
      listPageError: null,
    });
    listEpochRef.current += 1;
    detailEpochRef.current += 1;
  }, [session.id]);

  useEffect(() => {
    if (!canRead) return undefined;
    const controller = new AbortController();
    const epoch = listEpochRef.current + 1;
    listEpochRef.current = epoch;
    const expectedSessionId = session.id;
    updateWorkspaceState({
      listState: { kind: "loading" },
      loadingMore: false,
      listPageError: null,
    });
    void api
      .listPlatformLocalAccounts({
        includeDisabled,
        signal: controller.signal,
      })
      .then((page) => {
        if (
          controller.signal.aborted ||
          listEpochRef.current !== epoch ||
          sessionIdRef.current !== expectedSessionId
        ) {
          return;
        }
        setListState({
          items: page.items,
          kind: "ready",
          ...(page.nextCursor === undefined
            ? {}
            : { nextCursor: page.nextCursor }),
        });
      })
      .catch((caught: unknown) => {
        if (
          controller.signal.aborted ||
          listEpochRef.current !== epoch ||
          sessionIdRef.current !== expectedSessionId
        ) {
          return;
        }
        setListState({
          kind: "error",
          message: handleError(
            caught,
            "The local recovery account inventory could not be loaded.",
            expectedSessionId,
          ),
        });
      });
    return () => controller.abort();
  }, [
    setListState,
    api,
    canRead,
    handleError,
    includeDisabled,
    revision,
    session.id,
  ]);

  async function loadMoreAccounts(): Promise<void> {
    if (
      listState.kind !== "ready" ||
      listState.nextCursor === undefined ||
      loadingMore
    ) {
      return;
    }
    const cursor = listState.nextCursor;
    const epoch = listEpochRef.current;
    const expectedSessionId = session.id;
    updateWorkspaceState({ loadingMore: true, listPageError: null });
    try {
      const page = await api.listPlatformLocalAccounts({
        after: cursor,
        includeDisabled,
      });
      if (
        listEpochRef.current !== epoch ||
        sessionIdRef.current !== expectedSessionId
      ) {
        return;
      }
      setListState((current) => {
        if (current.kind !== "ready" || current.nextCursor !== cursor) {
          return current;
        }
        return {
          items: [...current.items, ...page.items],
          kind: "ready",
          ...(page.nextCursor === undefined
            ? {}
            : { nextCursor: page.nextCursor }),
        };
      });
    } catch (caught) {
      if (
        listEpochRef.current === epoch &&
        sessionIdRef.current === expectedSessionId
      ) {
        setListPageError(
          handleError(
            caught,
            "The next local recovery account page could not be loaded.",
            expectedSessionId,
          ),
        );
      }
    } finally {
      if (
        listEpochRef.current === epoch &&
        sessionIdRef.current === expectedSessionId
      ) {
        // react-doctor-disable-next-line no-loading-flag-reset-outside-finally -- The owning request clears this flag in finally; the generation guard protects newer requests.
        setLoadingMore(false);
      }
    }
  }

  const openAccount = useCallback(
    (accountId: string): void => {
      const epoch = detailEpochRef.current + 1;
      detailEpochRef.current = epoch;
      const expectedSessionId = session.id;
      updateWorkspaceState({
        selectedAccountId: accountId,
        detailState: { kind: "loading" },
      });
      void api
        .getPlatformLocalAccount(accountId)
        .then((resource) => {
          if (
            detailEpochRef.current === epoch &&
            sessionIdRef.current === expectedSessionId
          ) {
            setDetailState({ kind: "ready", resource });
          }
        })
        .catch((caught: unknown) => {
          if (
            detailEpochRef.current === epoch &&
            sessionIdRef.current === expectedSessionId
          ) {
            setDetailState({
              kind: "error",
              message: handleError(
                caught,
                "The current local account representation could not be loaded.",
                expectedSessionId,
              ),
            });
          }
        });
    },
    [setDetailState, api, handleError, session.id],
  );

  function closeAccount(): void {
    detailEpochRef.current += 1;
    updateWorkspaceState({
      selectedAccountId: null,
      detailState: { kind: "loading" },
    });
  }

  function acceptMutation(mutation: PlatformLocalAccountMutationView): void {
    updateWorkspaceState({
      listState: (current) => {
        if (current.kind !== "ready") return current;
        const items: (typeof current.items)[number][] = [];
        for (const previous of current.items) {
          const account =
            previous.id === mutation.account.value.id
              ? mutation.account.value
              : previous;
          if (includeDisabled || account.status !== "disabled")
            items.push(account);
        }
        items.sort((first, second) => first.id.localeCompare(second.id));
        return {
          items,
          kind: "ready",
          ...(current.nextCursor === undefined
            ? {}
            : { nextCursor: current.nextCursor }),
        };
      },
      detailState: { kind: "ready", resource: mutation.account },
    });
    if (mutation.ceremonyToken && mutation.totpEnrollment) {
      setNotice({
        accountLabel: mutation.account.value.displayName,
        kind:
          mutation.account.value.status === "invited"
            ? "invitation"
            : "recovery",
        provisioningUri: mutation.totpEnrollment.provisioningUri,
        secret: mutation.totpEnrollment.secret,
        sessionId: session.id,
        token: mutation.ceremonyToken,
      });
    } else {
      setNotice(null);
    }
  }

  if (!canRead) {
    return {
      kind: "content" as const,
      content: (
        <section className="content-stack">
          <div className="page-heading">
            <div>
              <p className="eyebrow">Platform recovery</p>
              <h1>Local recovery accounts</h1>
            </div>
          </div>
          <FocusedError message="Your current platform session cannot read local recovery accounts. Server authorization is enforced independently of this page." />
        </section>
      ),
    };
  }

  const accounts = listState.kind === "ready" ? listState.items : [];
  const readyProtectedCount = accounts.filter(
    (account) =>
      account.protectedRecoveryPrincipal && account.status === "active",
  ).length;

  return {
    kind: "ready" as const,
    data: {
      acceptMutation,
      api,
      canManage,
      closeAccount,
      detailState,
      includeDisabled,
      inviteOpen,
      listPageError,
      listState,
      loadMoreAccounts,
      loadingMore,
      openAccount,
      readyProtectedCount,
      selectedAccountId,
      session,
      setIncludeDisabled,
      setInviteOpen,
      setNotice,
      setRevision,
      visibleNotice,
    },
  };
}

function PlatformLocalAccountsPageView({
  model,
}: {
  model: Extract<
    ReturnType<typeof usePlatformLocalAccountsPageModel>,
    { kind: "ready" }
  >["data"];
}): React.JSX.Element {
  const {
    acceptMutation,
    api,
    canManage,
    closeAccount,
    detailState,
    inviteOpen,
    selectedAccountId,
    session,
    setInviteOpen,
    setRevision,
  } = model;
  return (
    <section className="content-stack platform-local-account-page">
      <LocalAccountPageHeading model={model} />

      {<LocalAccountCreationCeremony model={model} />}

      <PlatformLocalAccountsPageRecoveryPosture model={model} />

      <PlatformLocalAccountsPageAccountInventory model={model} />

      <InviteLocalAccountDialog
        api={api}
        canManage={canManage}
        csrfToken={session.csrfToken}
        onCreated={(created) => {
          acceptMutation(created);
          setRevision((value) => value + 1);
          setInviteOpen(false);
        }}
        onOpenChange={setInviteOpen}
        open={inviteOpen}
        sessionId={session.id}
      />

      <ManageLocalAccountDialog
        api={api}
        canManage={canManage}
        csrfToken={session.csrfToken}
        detailState={detailState}
        onClose={closeAccount}
        onMutation={acceptMutation}
        open={selectedAccountId !== null}
        sessionId={session.id}
      />
    </section>
  );
}

interface InviteDialogProps {
  api: ReturnType<typeof useSession>["api"];
  canManage: boolean;
  csrfToken: string;
  onCreated: (result: PlatformLocalAccountInvitationView) => void;
  onOpenChange: (open: boolean) => void;
  open: boolean;
  sessionId: string;
}

function InviteLocalAccountDialog({
  api,
  canManage,
  csrfToken,
  onCreated,
  onOpenChange,
  open,
  sessionId,
}: InviteDialogProps): React.JSX.Element {
  const displayNameId = useId();
  const loginId = useId();
  const reasonId = useId();
  const protectedId = useId();
  const [workspaceState, updateWorkspaceState] = useReducer(
    reduceWorkspaceState<InviteLocalAccountDialogState>,
    undefined,
    (): InviteLocalAccountDialogState => ({
      displayName: "",
      loginIdentifier: "",
      protectedPrincipal: true,
      reason: "",
      error: null,
      busy: false,
    }),
  );
  const {
    displayName,
    loginIdentifier,
    protectedPrincipal,
    reason,
    error,
    busy,
  } = workspaceState;
  const {
    setDisplayName,
    setLoginIdentifier,
    setProtectedPrincipal,
    setReason,
    setError,
    setBusy,
  } = useMemo(
    () => ({
      setDisplayName: (
        value: React.SetStateAction<
          InviteLocalAccountDialogState["displayName"]
        >,
      ) => updateWorkspaceState({ displayName: value }),
      setLoginIdentifier: (
        value: React.SetStateAction<
          InviteLocalAccountDialogState["loginIdentifier"]
        >,
      ) => updateWorkspaceState({ loginIdentifier: value }),
      setProtectedPrincipal: (
        value: React.SetStateAction<
          InviteLocalAccountDialogState["protectedPrincipal"]
        >,
      ) => updateWorkspaceState({ protectedPrincipal: value }),
      setReason: (
        value: React.SetStateAction<InviteLocalAccountDialogState["reason"]>,
      ) => updateWorkspaceState({ reason: value }),
      setError: (
        value: React.SetStateAction<InviteLocalAccountDialogState["error"]>,
      ) => updateWorkspaceState({ error: value }),
      setBusy: (
        value: React.SetStateAction<InviteLocalAccountDialogState["busy"]>,
      ) => updateWorkspaceState({ busy: value }),
    }),
    [updateWorkspaceState],
  );

  const idempotencyKeyRef = useRef<string | null>(null);

  const reset = useCallback((): void => {
    updateWorkspaceState({
      displayName: "",
      loginIdentifier: "",
      protectedPrincipal: true,
      reason: "",
      error: null,
      busy: false,
    });
    idempotencyKeyRef.current = null;
  }, []);

  useEffect(() => reset(), [reset, sessionId]);

  async function submit(
    event: React.FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault();
    if (!canManage || busy) return;
    const name = displayName.trim();
    const login = loginIdentifier.trim().toLowerCase();
    const auditReason = reason.trim();
    if (
      !validBoundedUtf8(name, 1, 160) ||
      !validBoundedUtf8(login, 3, 320) ||
      !login.includes("@") ||
      !validAuditReason(auditReason)
    ) {
      setError(
        "Enter a bounded display name, lowercase email, and visible-ASCII audit reason without commas.",
      );
      return;
    }
    idempotencyKeyRef.current ??= globalThis.crypto.randomUUID();
    updateWorkspaceState({ busy: true, error: null });
    try {
      const result = await api.invitePlatformLocalAccount(
        csrfToken,
        idempotencyKeyRef.current,
        auditReason,
        {
          displayName: name,
          loginIdentifier: login,
          protectedRecoveryPrincipal: protectedPrincipal,
        },
      );
      idempotencyKeyRef.current = null;
      reset();
      onCreated(result);
    } catch (caught) {
      setError(
        describePhaseTwoError(
          caught,
          "The recovery account invitation could not be created. Retry the unchanged request safely.",
        ),
      );
    } finally {
      setBusy(false);
    }
  }

  function changed(update: () => void): void {
    idempotencyKeyRef.current = null;
    update();
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(nextOpen) => {
        if (!nextOpen) reset();
        onOpenChange(nextOpen);
      }}
    >
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Invite a local recovery account</DialogTitle>
          <DialogDescription>
            Login remains disabled until the one-time token, password, and local
            factor ceremony are completed.
          </DialogDescription>
        </DialogHeader>
        <form
          className="platform-local-account-form"
          aria-label="Invite local recovery account"
          onSubmit={(event) => void submit(event)}
        >
          {error ? <FocusedError message={error} /> : null}
          <FormField htmlFor={displayNameId} label="Display name">
            <Input
              id={displayNameId}
              value={displayName}
              maxLength={160}
              autoComplete="off"
              onChange={(event) =>
                changed(() => setDisplayName(event.target.value))
              }
            />
          </FormField>
          <FormField htmlFor={loginId} label="Login email">
            <Input
              id={loginId}
              value={loginIdentifier}
              maxLength={320}
              type="email"
              autoComplete="off"
              onChange={(event) =>
                changed(() => setLoginIdentifier(event.target.value))
              }
            />
          </FormField>
          <div className="platform-local-account-check">
            <Checkbox
              id={protectedId}
              checked={protectedPrincipal}
              onCheckedChange={(checked) =>
                changed(() => setProtectedPrincipal(checked === true))
              }
            />
            <div>
              <Label htmlFor={protectedId}>Protected recovery principal</Label>
              <small>
                Include this account in the locked last-ready-recovery check.
              </small>
            </div>
          </div>
          <FormField
            htmlFor={reasonId}
            label="Audit reason"
            hint="Visible ASCII only; do not include credentials, tokens, identifiers, or customer data."
          >
            <Input
              id={reasonId}
              value={reason}
              maxLength={500}
              autoComplete="off"
              onChange={(event) => changed(() => setReason(event.target.value))}
            />
          </FormField>
          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => {
                reset();
                onOpenChange(false);
              }}
            >
              Cancel
            </Button>
            <Button type="submit" disabled={busy || !canManage}>
              {busy ? "Inviting…" : "Invite account"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

interface ManageDialogProps {
  api: ReturnType<typeof useSession>["api"];
  canManage: boolean;
  csrfToken: string;
  detailState: DetailState;
  onClose: () => void;
  onMutation: (result: PlatformLocalAccountMutationView) => void;
  open: boolean;
  sessionId: string;
}

function ManageLocalAccountDialog(props: ManageDialogProps): React.JSX.Element {
  const model = useManageLocalAccountDialogModel(props);
  return <ManageLocalAccountDialogView model={model.data} />;
}

function useManageLocalAccountDialogModel({
  api,
  canManage,
  csrfToken,
  detailState,
  onClose,
  onMutation,
  open,
  sessionId,
}: ManageDialogProps) {
  const reasonId = useId();
  const tokenId = useId();
  const passwordId = useId();
  const factorId = useId();
  const [workspaceState, updateWorkspaceState] = useReducer(
    reduceWorkspaceState<ManageLocalAccountDialogState>,
    undefined,
    (): ManageLocalAccountDialogState => ({
      reason: "",
      ceremonyToken: "",
      newPassword: "",
      factorProof: "",
      error: null,
      busyAction: null,
    }),
  );
  const { reason, ceremonyToken, newPassword, factorProof, error, busyAction } =
    workspaceState;
  const {
    setReason,
    setCeremonyToken,
    setNewPassword,
    setFactorProof,
    setError,
    setBusyAction,
  } = useMemo(
    () => ({
      setReason: (
        value: React.SetStateAction<ManageLocalAccountDialogState["reason"]>,
      ) => updateWorkspaceState({ reason: value }),
      setCeremonyToken: (
        value: React.SetStateAction<
          ManageLocalAccountDialogState["ceremonyToken"]
        >,
      ) => updateWorkspaceState({ ceremonyToken: value }),
      setNewPassword: (
        value: React.SetStateAction<
          ManageLocalAccountDialogState["newPassword"]
        >,
      ) => updateWorkspaceState({ newPassword: value }),
      setFactorProof: (
        value: React.SetStateAction<
          ManageLocalAccountDialogState["factorProof"]
        >,
      ) => updateWorkspaceState({ factorProof: value }),
      setError: (
        value: React.SetStateAction<ManageLocalAccountDialogState["error"]>,
      ) => updateWorkspaceState({ error: value }),
      setBusyAction: (
        value: React.SetStateAction<
          ManageLocalAccountDialogState["busyAction"]
        >,
      ) => updateWorkspaceState({ busyAction: value }),
    }),
    [updateWorkspaceState],
  );

  const idempotencyKeyRef = useRef<string | null>(null);

  const clearSensitiveDraft = useCallback((): void => {
    updateWorkspaceState({
      ceremonyToken: "",
      newPassword: "",
      factorProof: "",
    });
  }, []);

  const reset = useCallback((): void => {
    setReason("");
    clearSensitiveDraft();
    updateWorkspaceState({ error: null, busyAction: null });
    idempotencyKeyRef.current = null;
  }, [setReason, clearSensitiveDraft]);

  useEffect(() => reset(), [open, reset, sessionId]);

  function changed(update: () => void): void {
    idempotencyKeyRef.current = null;
    update();
  }

  async function mutate(
    action: "activate" | "disable" | "enable" | "recover" | "rotate",
  ): Promise<void> {
    if (detailState.kind !== "ready" || !canManage || busyAction) return;
    const auditReason = reason.trim();
    if (!validAuditReason(auditReason)) {
      setError(
        "Enter a visible-ASCII audit reason of 500 characters or fewer without commas.",
      );
      return;
    }
    if (
      action === "activate" &&
      (!ceremonyTokenPattern.test(ceremonyToken) ||
        !validBoundedUtf8(newPassword, 14, 1024) ||
        !/^(?:\d{6}|\d{8})$/.test(factorProof))
    ) {
      setError(
        "Activation requires the canonical 43-character token, a 14–1024 character password, and a 6- or 8-digit factor proof.",
      );
      return;
    }
    if (action === "rotate" && !validBoundedUtf8(newPassword, 14, 1024)) {
      setError("Use a new password between 14 and 1024 characters.");
      return;
    }
    idempotencyKeyRef.current ??= globalThis.crypto.randomUUID();
    updateWorkspaceState({ busyAction: action, error: null });
    const resource = detailState.resource;
    try {
      let result: PlatformLocalAccountMutationView;
      switch (action) {
        case "activate":
          result = await api.activatePlatformLocalAccount(
            csrfToken,
            resource.value.id,
            resource,
            idempotencyKeyRef.current,
            auditReason,
            { ceremonyToken, factorProof, newPassword },
          );
          break;
        case "disable":
          result = await api.disablePlatformLocalAccount(
            csrfToken,
            resource.value.id,
            resource,
            idempotencyKeyRef.current,
            auditReason,
          );
          break;
        case "enable":
          result = await api.enablePlatformLocalAccount(
            csrfToken,
            resource.value.id,
            resource,
            idempotencyKeyRef.current,
            auditReason,
          );
          break;
        case "recover":
          result = await api.recoverPlatformLocalAccount(
            csrfToken,
            resource.value.id,
            resource,
            idempotencyKeyRef.current,
            auditReason,
          );
          break;
        case "rotate":
          result = await api.rotatePlatformLocalAccountPassword(
            csrfToken,
            resource.value.id,
            resource,
            idempotencyKeyRef.current,
            auditReason,
            { newPassword },
          );
      }
      idempotencyKeyRef.current = null;
      setReason("");
      clearSensitiveDraft();
      onMutation(result);
    } catch (caught) {
      setError(
        describePhaseTwoError(
          caught,
          "The local-account transition could not be completed. Retry the unchanged request safely or refresh the account.",
        ),
      );
    } finally {
      setBusyAction(null);
    }
  }

  const account =
    detailState.kind === "ready" ? detailState.resource.value : null;
  const activationAvailable =
    account?.status === "invited" || account?.status === "recovery_restricted";

  return {
    kind: "ready" as const,
    data: {
      account,
      activationAvailable,
      busyAction,
      canManage,
      ceremonyToken,
      changed,
      detailState,
      error,
      factorId,
      factorProof,
      mutate,
      newPassword,
      onClose,
      open,
      passwordId,
      reason,
      reasonId,
      reset,
      setCeremonyToken,
      setFactorProof,
      setNewPassword,
      setReason,
      tokenId,
    },
  };
}

function ManageLocalAccountDialogView({
  model,
}: {
  model: Extract<
    ReturnType<typeof useManageLocalAccountDialogModel>,
    { kind: "ready" }
  >["data"];
}): React.JSX.Element {
  return <LocalAccountDialogContent model={model} />;
}

interface SecretFieldsProps {
  factorId: string;
  factorProof: string;
  newPassword: string;
  onFactorChange: (value: string) => void;
  onPasswordChange: (value: string) => void;
  passwordId: string;
  showFactor?: boolean;
}

function SecretFields({
  factorId,
  factorProof,
  newPassword,
  onFactorChange,
  onPasswordChange,
  passwordId,
  showFactor = false,
}: SecretFieldsProps): React.JSX.Element {
  return (
    <div className="platform-local-account-secret-grid">
      <FormField
        htmlFor={passwordId}
        label="New password"
        hint="14–1024 characters; checked against retained history."
      >
        <Input
          id={passwordId}
          value={newPassword}
          type="password"
          minLength={14}
          maxLength={1024}
          autoComplete="new-password"
          onChange={(event) => onPasswordChange(event.target.value)}
        />
      </FormField>
      {showFactor ? (
        <FormField htmlFor={factorId} label="Local factor proof">
          <Input
            id={factorId}
            value={factorProof}
            inputMode="numeric"
            minLength={6}
            maxLength={8}
            autoComplete="one-time-code"
            onChange={(event) => onFactorChange(event.target.value)}
          />
        </FormField>
      ) : null}
    </div>
  );
}

function validBoundedUtf8(
  value: string,
  minimum: number,
  maximum: number,
): boolean {
  const bytes = platformUtf8ByteLength(value);
  return bytes >= minimum && bytes <= maximum;
}

function validAuditReason(value: string): boolean {
  return (
    value.length >= 1 && value.length <= 500 && auditReasonPattern.test(value)
  );
}

function statusLabel(status: PlatformLocalAccountView["status"]): string {
  return {
    active: "Active",
    disabled: "Disabled",
    invited: "Invited",
    recovery_restricted: "Recovery restricted",
  }[status];
}

function statusBadgeVariant(
  status: PlatformLocalAccountView["status"],
): "default" | "destructive" | "outline" | "secondary" {
  const variants = {
    active: "default",
    disabled: "secondary",
    invited: "outline",
    recovery_restricted: "destructive",
  } as const;
  return variants[status];
}

function PlatformLocalAccountsPageAccountInventory({
  model,
}: {
  model: React.ComponentProps<typeof PlatformLocalAccountsPageView>["model"];
}): React.ReactNode {
  const { includeDisabled, setIncludeDisabled } = model;
  return (
    <Card className="platform-local-account-inventory">
      <CardHeader className="platform-local-account-inventory-header">
        <div>
          <CardTitle>Account inventory</CardTitle>
          <CardDescription>
            Safe lifecycle projections only. Credentials, factors, ceremony
            digests, recovery codes, and session provenance never appear.
          </CardDescription>
        </div>
        <div className="platform-local-account-filter">
          <Checkbox
            id="platform-local-account-show-disabled"
            checked={includeDisabled}
            onCheckedChange={(checked) => setIncludeDisabled(checked === true)}
          />
          <Label htmlFor="platform-local-account-show-disabled">
            Show disabled accounts
          </Label>
        </div>
      </CardHeader>
      <LocalAccountInventoryContent model={model} />
    </Card>
  );
}

function LocalAccountDialogContent({
  model,
}: {
  model: React.ComponentProps<typeof ManageLocalAccountDialogView>["model"];
}): React.ReactNode {
  const {
    account,
    canManage,
    changed,
    detailState,
    error,
    onClose,
    open,
    reason,
    reasonId,
    reset,
    setReason,
  } = model;
  return (
    <Dialog
      open={open}
      onOpenChange={(nextOpen) => {
        if (!nextOpen) {
          reset();
          onClose();
        }
      }}
    >
      <DialogContent className="platform-local-account-dialog">
        <DialogHeader>
          <DialogTitle>
            {canManage ? "Manage" : "Inspect"} local recovery account
          </DialogTitle>
          <DialogDescription>
            The database rechecks live platform authority, fresh local MFA,
            current revision, and the recovery floor before committing.
          </DialogDescription>
        </DialogHeader>
        {detailState.kind === "loading" ? (
          <p aria-live="polite">Loading the current account revision…</p>
        ) : null}
        {detailState.kind === "error" ? (
          <FocusedError message={detailState.message} />
        ) : null}
        {account ? (
          <div className="platform-local-account-detail">
            <div className="platform-local-account-detail__identity">
              <div>
                <span>Operator</span>
                <strong>{account.displayName}</strong>
                <small>{account.loginIdentifier}</small>
              </div>
              <Badge variant={statusBadgeVariant(account.status)}>
                {statusLabel(account.status)} · v{account.revision}
              </Badge>
            </div>
            <dl>
              <div>
                <dt>Credential generation</dt>
                <dd>{account.credentialVersion}</dd>
              </div>
              <div>
                <dt>Confirmed factors</dt>
                <dd>{account.confirmedAcceptableFactors}</dd>
              </div>
              <div>
                <dt>Identity epoch</dt>
                <dd>{account.identityEpoch}</dd>
              </div>
            </dl>
            {canManage ? (
              <div className="platform-local-account-form">
                {error ? <FocusedError message={error} /> : null}
                <FormField
                  htmlFor={reasonId}
                  label="Audit reason"
                  hint="Visible ASCII only. Never include secrets, identifiers, or customer data."
                >
                  <Input
                    id={reasonId}
                    value={reason}
                    maxLength={500}
                    autoComplete="off"
                    onChange={(event) =>
                      changed(() => setReason(event.target.value))
                    }
                  />
                </FormField>
                {<LocalAccountPasswordCeremony model={model} />}
                {<LocalAccountTotpCeremony model={model} />}
                <LocalAccountLifecycleActions model={model} />
              </div>
            ) : (
              <Alert>
                <CircleAlert aria-hidden="true" />
                <AlertTitle>Read-only platform access</AlertTitle>
                <AlertDescription>
                  Lifecycle controls require both platform identity-account read
                  and manage permissions.
                </AlertDescription>
              </Alert>
            )}
          </div>
        ) : null}
        <DialogFooter>
          <Button
            type="button"
            variant="outline"
            onClick={() => {
              reset();
              onClose();
            }}
          >
            Close
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

interface PlatformLocalAccountsPageState {
  includeDisabled: boolean;
  listState: AccountListState;
  revision: number;
  loadingMore: boolean;
  listPageError: string | null;
  inviteOpen: boolean;
  selectedAccountId: string | null;
  detailState: DetailState;
  notice: CeremonyNotice | null;
}

interface ManageLocalAccountDialogState {
  reason: string;
  ceremonyToken: string;
  newPassword: string;
  factorProof: string;
  error: string | null;
  busyAction: string | null;
}

interface InviteLocalAccountDialogState {
  displayName: string;
  loginIdentifier: string;
  protectedPrincipal: boolean;
  reason: string;
  error: string | null;
  busy: boolean;
}

function LocalAccountPageHeading({
  model,
}: {
  model: React.ComponentProps<typeof PlatformLocalAccountsPageView>["model"];
}): React.ReactNode {
  const { canManage, setInviteOpen, setRevision } = model;
  return (
    <div className="page-heading platform-local-account-heading">
      <div>
        <p className="eyebrow">Platform recovery</p>
        <h1>Local recovery accounts</h1>
        <p>
          Keep an independently authenticated path into the platform. Every
          lifecycle change requires a fresh local factor and leaves a redacted
          audit record.
        </p>
      </div>
      <div className="platform-local-account-heading__actions">
        <Button
          type="button"
          variant="outline"
          onClick={() => setRevision((value) => value + 1)}
        >
          <RefreshCw aria-hidden="true" /> Refresh
        </Button>
        {canManage ? (
          <Button type="button" onClick={() => setInviteOpen(true)}>
            <Plus aria-hidden="true" /> Invite recovery account
          </Button>
        ) : null}
      </div>
    </div>
  );
}

function LocalAccountCreationCeremony({
  model,
}: {
  model: React.ComponentProps<typeof PlatformLocalAccountsPageView>["model"];
}): React.ReactNode {
  const { setNotice, visibleNotice } = model;
  return visibleNotice ? (
    <Alert className="platform-local-account-token">
      <KeyRound aria-hidden="true" />
      <AlertTitle>
        One-time {visibleNotice.kind} token for {visibleNotice.accountLabel}
      </AlertTitle>
      <AlertDescription>
        <p>
          Enroll the authenticator and transfer the ceremony token through the
          approved secure channel now. None of this material can be read again,
          and an exact retry will not return it.
        </p>
        <dl className="platform-local-account-enrollment-material">
          <div>
            <dt>Ceremony token</dt>
            <dd>
              <code>{visibleNotice.token}</code>
            </dd>
          </div>
          <div>
            <dt>TOTP secret</dt>
            <dd>
              <code>{visibleNotice.secret}</code>
            </dd>
          </div>
          <div>
            <dt>Authenticator URI</dt>
            <dd>
              <code>{visibleNotice.provisioningUri}</code>
            </dd>
          </div>
        </dl>
        <Button
          type="button"
          size="sm"
          variant="outline"
          onClick={() => setNotice(null)}
        >
          I have stored the enrollment material
        </Button>
      </AlertDescription>
    </Alert>
  ) : null;
}

function PlatformLocalAccountsPageRecoveryPosture({
  model,
}: {
  model: React.ComponentProps<typeof PlatformLocalAccountsPageView>["model"];
}): React.ReactNode {
  const { readyProtectedCount } = model;
  return (
    <Card className="platform-local-account-posture">
      <CardHeader>
        <div>
          <CardTitle>Recovery posture</CardTitle>
          <CardDescription>
            The backend prevents an action that would remove the last ready
            protected human recovery principal.
          </CardDescription>
        </div>
        <Badge variant={readyProtectedCount > 1 ? "secondary" : "destructive"}>
          {readyProtectedCount} ready protected
        </Badge>
      </CardHeader>
      <CardContent>
        <div
          className="platform-local-account-recovery-rail"
          data-state={readyProtectedCount > 1 ? "redundant" : "at-risk"}
        >
          <span aria-hidden="true" />
          <div>
            <strong>
              {readyProtectedCount > 1
                ? "Recovery has redundancy"
                : "Recovery floor needs attention"}
            </strong>
            <small>
              Inventory signals are informative; the locked database check
              decides whether a mutation is safe.
            </small>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function LocalAccountInventoryContent({
  model,
}: {
  model: React.ComponentProps<
    typeof PlatformLocalAccountsPageAccountInventory
  >["model"];
}): React.ReactNode {
  const {
    canManage,
    listPageError,
    listState,
    loadMoreAccounts,
    loadingMore,
    openAccount,
  } = model;
  return (
    <CardContent>
      {listState.kind === "loading" ? (
        <p aria-live="polite">Loading local recovery accounts…</p>
      ) : null}
      {listState.kind === "error" ? (
        <FocusedError message={listState.message} />
      ) : null}
      {listState.kind === "ready" && listState.items.length === 0 ? (
        <div className="platform-local-account-empty">
          <ShieldCheck aria-hidden="true" />
          <div>
            <strong>No local recovery accounts are visible.</strong>
            <p>
              Invite a reviewed emergency operator before relying on this
              authentication path.
            </p>
          </div>
        </div>
      ) : null}
      {listState.kind === "ready" && listState.items.length > 0 ? (
        <Table className="platform-local-account-table">
          <TableCaption>
            Local recovery accounts ordered by immutable account ID.
          </TableCaption>
          <TableHeader>
            <TableRow>
              <TableHead>Operator</TableHead>
              <TableHead>Lifecycle</TableHead>
              <TableHead>Recovery role</TableHead>
              <TableHead>Revision</TableHead>
              <TableHead className="text-right">Controls</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {listState.items.map((account) => (
              <TableRow key={account.id} data-state={account.status}>
                <TableCell>
                  <strong>{account.displayName}</strong>
                  <small>{account.loginIdentifier}</small>
                </TableCell>
                <TableCell>
                  <Badge variant={statusBadgeVariant(account.status)}>
                    {statusLabel(account.status)}
                  </Badge>
                </TableCell>
                <TableCell>
                  {account.protectedRecoveryPrincipal
                    ? "Protected principal"
                    : "Standard local account"}
                </TableCell>
                <TableCell>v{account.revision}</TableCell>
                <TableCell className="text-right">
                  <Button
                    type="button"
                    size="sm"
                    variant="outline"
                    onClick={() => openAccount(account.id)}
                  >
                    {canManage ? "Manage" : "Inspect"}
                    <span className="sr-only"> {account.displayName}</span>
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      ) : null}
      {listPageError ? <FocusedError message={listPageError} /> : null}
      {listState.kind === "ready" && listState.nextCursor ? (
        <div className="platform-local-account-load-more">
          <Button
            type="button"
            variant="outline"
            disabled={loadingMore}
            onClick={() => void loadMoreAccounts()}
          >
            {loadingMore ? "Loading…" : "Load more accounts"}
          </Button>
        </div>
      ) : null}
    </CardContent>
  );
}

function LocalAccountPasswordCeremony({
  model,
}: {
  model: React.ComponentProps<typeof LocalAccountDialogContent>["model"];
}): React.ReactNode {
  const {
    activationAvailable,
    busyAction,
    ceremonyToken,
    changed,
    factorId,
    factorProof,
    mutate,
    newPassword,
    passwordId,
    setCeremonyToken,
    setFactorProof,
    setNewPassword,
    tokenId,
  } = model;
  return activationAvailable ? (
    <div className="platform-local-account-ceremony">
      <p className="section-label">Activation ceremony</p>
      <FormField htmlFor={tokenId} label="One-time token">
        <Input
          id={tokenId}
          value={ceremonyToken}
          minLength={43}
          maxLength={43}
          autoComplete="off"
          spellCheck={false}
          onChange={(event) =>
            changed(() => setCeremonyToken(event.target.value))
          }
        />
      </FormField>
      <SecretFields
        factorId={factorId}
        factorProof={factorProof}
        passwordId={passwordId}
        newPassword={newPassword}
        onFactorChange={(value) => changed(() => setFactorProof(value))}
        onPasswordChange={(value) => changed(() => setNewPassword(value))}
        showFactor
      />
      <Button
        type="button"
        disabled={busyAction !== null}
        onClick={() => void mutate("activate")}
      >
        {busyAction === "activate" ? "Activating…" : "Complete activation"}
      </Button>
    </div>
  ) : null;
}

function LocalAccountTotpCeremony({
  model,
}: {
  model: React.ComponentProps<typeof LocalAccountDialogContent>["model"];
}): React.ReactNode {
  const {
    account,
    busyAction,
    changed,
    factorId,
    factorProof,
    mutate,
    newPassword,
    passwordId,
    setFactorProof,
    setNewPassword,
  } = model;
  if (!account) return null;
  return account.status === "active" ? (
    <div className="platform-local-account-ceremony">
      <p className="section-label">Credential replacement</p>
      <SecretFields
        factorId={factorId}
        factorProof={factorProof}
        passwordId={passwordId}
        newPassword={newPassword}
        onFactorChange={(value) => changed(() => setFactorProof(value))}
        onPasswordChange={(value) => changed(() => setNewPassword(value))}
      />
      <Button
        type="button"
        variant="outline"
        disabled={busyAction !== null}
        onClick={() => void mutate("rotate")}
      >
        {busyAction === "rotate" ? "Rotating…" : "Rotate password"}
      </Button>
    </div>
  ) : null;
}

function LocalAccountLifecycleActions({
  model,
}: {
  model: React.ComponentProps<typeof LocalAccountDialogContent>["model"];
}): React.ReactNode {
  const { account, busyAction, mutate } = model;
  if (!account) return null;
  return (
    <div className="platform-local-account-lifecycle-actions">
      {account.status === "disabled" ? (
        <Button
          type="button"
          disabled={busyAction !== null}
          onClick={() => void mutate("enable")}
        >
          {busyAction === "enable" ? "Enabling…" : "Enable account"}
        </Button>
      ) : null}
      {account.status === "active" ||
      account.status === "recovery_restricted" ? (
        <Button
          type="button"
          variant="destructive"
          disabled={busyAction !== null}
          onClick={() => void mutate("disable")}
        >
          {busyAction === "disable"
            ? "Disabling…"
            : "Disable and revoke sessions"}
        </Button>
      ) : null}
      {account.status === "active" || account.status === "disabled" ? (
        <Button
          type="button"
          variant="outline"
          disabled={busyAction !== null}
          onClick={() => void mutate("recover")}
        >
          {busyAction === "recover"
            ? "Starting recovery…"
            : "Start restricted recovery"}
        </Button>
      ) : null}
    </div>
  );
}
