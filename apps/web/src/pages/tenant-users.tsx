import {
  Alert,
  AlertDescription,
  AlertTitle,
} from "@periapsis/ui/components/ui/alert";
import { Badge } from "@periapsis/ui/components/ui/badge";
import { Button } from "@periapsis/ui/components/ui/button";
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
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@periapsis/ui/components/ui/select";
import {
  Table,
  TableBody,
  TableCaption,
  TableCell,
  TableRow,
} from "@periapsis/ui/components/ui/table";
import { Textarea } from "@periapsis/ui/components/ui/textarea";
import {
  ArrowDown,
  Ban,
  KeyRound,
  Plus,
  RefreshCw,
  RotateCcw,
  ShieldCheck,
  Trash2,
  UserRound,
  Users,
} from "lucide-react";
import {
  useEffect,
  useId,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { Controller, useForm, useWatch } from "react-hook-form";
import { z } from "zod";
import { TableColumnHeaders } from "../components/table-column-headers";
import { TenantRequiredPage } from "../components/tenant-required-page";
import {
  deriveDelegableRoleChoice,
  effectiveAuthorityPathKey,
  mergeTenantUsers,
  type DelegableRoleChoice,
} from "./tenant-users-model";

import { useSession } from "../auth/session-context";
import { useTenantAuthority } from "../auth/tenant-authority-context";
import { FocusedError } from "../components/focused-error";
import { FormField } from "../components/form-field";
import { ServerDenied } from "../components/server-denied";
import {
  idempotencyKeyForPayload,
  isPayloadBoundToIdempotencyKey,
} from "../lib/payload-idempotency";
import {
  describePhaseTwoError,
  PhaseTwoApiError,
  type DirectUserRoleGrantView,
  type EffectiveTenantDelegationView,
  type EffectiveTenantRoleGrantView,
  type PhaseTwoApi,
  type TenantMembershipLifecycleReceiptView,
  type TenantUserSummaryView,
} from "../lib/phase-two-types";
import {
  currentInstant,
  hasInstantReached,
  parseRfc3339Instant,
} from "../lib/rfc3339-instant";
import { hasControlCharacters } from "../lib/text-validation";
import { AccessPathRail } from "./tenant-group-detail";

const dateTimeFormatter = new Intl.DateTimeFormat(undefined, {
  day: "2-digit",
  hour: "2-digit",
  minute: "2-digit",
  month: "short",
  timeZoneName: "short",
  year: "numeric",
});

type UserListState =
  | { kind: "error"; message: string }
  | { kind: "forbidden" }
  | { kind: "inactive" }
  | {
      items: readonly TenantUserSummaryView[];
      kind: "ready";
      nextCursor?: string;
    }
  | { kind: "loading" };

type GrantListState =
  | { kind: "error"; message: string }
  | { kind: "forbidden" }
  | {
      items: readonly DirectGrantEntry[];
      kind: "ready";
      nextCursor?: string;
    }
  | { kind: "loading" };

interface DirectGrantEntry {
  grant: DirectUserRoleGrantView;
  originCursor?: string;
}

interface PairSnapshot<T> {
  pairKey: string;
  state: T;
}

interface UserSelection {
  generation: number;
  pairKey: string;
  user: TenantUserSummaryView;
}

interface LifecycleSelection {
  pairKey: string;
  user: TenantUserSummaryView;
}

interface PaginationRequest {
  controller: AbortController;
  cursor: string;
  generation: number;
  pairKey: string;
}

interface PaginationState {
  error?: string;
  loading: boolean;
}

interface GrantRefreshRequest {
  controller: AbortController;
}

interface RevokeDraft {
  error: string | null;
  notice: string | null;
  open: boolean;
  reason: string;
  refresh:
    | { kind: "idle" }
    | {
        entry: DirectGrantEntry;
        kind: "refreshing" | "required";
      };
  saving: boolean;
}

const emptyRevokeDraft: RevokeDraft = {
  error: null,
  notice: null,
  open: false,
  reason: "",
  refresh: { kind: "idle" },
  saving: false,
};

const maximumTimerDelay = 2_147_000_000;
const maximumDirectGrantVersion = 2_147_483_647;
const directGrantEntityTagPrefixPattern = /^"v([1-9][0-9]*)-/;

const reasonSchema = z
  .string()
  .trim()
  .min(1, "Enter an administrative reason.")
  .max(500, "Use 500 characters or fewer.")
  .refine(
    (value) => !hasControlCharacters(value),
    "Use a reason without control characters.",
  );

const lifecycleReasonSchema = z
  .string()
  .min(1, "Enter an administrative reason.")
  .max(2048, "Use 2,048 characters or fewer.")
  .refine(
    (value) => value.trim() === value,
    "Remove leading or trailing whitespace from the reason.",
  )
  .refine(
    (value) => !hasControlCharacters(value),
    "Use a reason without control characters.",
  );

const grantFormSchema = z.object({
  expiresAt: z.string(),
  reason: reasonSchema,
  roleId: z.string().min(1, "Select a role."),
});

type GrantFormValues = z.infer<typeof grantFormSchema>;

export function TenantUsersPage(): React.JSX.Element {
  const model = useTenantUsersPageModel();
  if (model.kind === "content") return model.content;
  return <TenantUsersPageView model={model.data} />;
}

function useTenantUsersPageModel() {
  const { api, clearSession, session } = useSession();
  const authority = useTenantAuthority();
  const tenantId = session.activeTenantId;
  const requestPair = JSON.stringify([session.id, tenantId ?? null]);
  const requestPairRef = useRef(requestPair);
  useLayoutEffect(() => {
    requestPairRef.current = requestPair;
  });
  const canRead = authority.hasPermission("user.read");
  const authorityReady =
    Boolean(tenantId) && authority.status === "ready" && canRead;
  const authorityReadyRef = useRef(authorityReady);
  useLayoutEffect(() => {
    authorityReadyRef.current = authorityReady;
  });
  const initialListState = useMemo(
    () =>
      deriveInitialUserListState(
        tenantId,
        authority.status,
        authority.message,
        canRead,
      ),
    [tenantId, authority.status, authority.message, canRead],
  );
  const [listSnapshot, setListSnapshot] = useState<PairSnapshot<UserListState>>(
    () => ({ pairKey: requestPair, state: initialListState }),
  );
  const listState =
    authorityReady && listSnapshot.pairKey === requestPair
      ? listSnapshot.state
      : initialListState;
  const [userSelection, setUserSelection] = useState<UserSelection | null>(
    null,
  );
  const userSelectionGenerationRef = useRef(0);
  const [loadAttempt, setLoadAttempt] = useState(0);
  const [paginationSnapshot, setPaginationSnapshot] = useState<
    PairSnapshot<PaginationState>
  >(() => ({ pairKey: requestPair, state: { loading: false } }));
  const paginationState =
    paginationSnapshot.pairKey === requestPair
      ? paginationSnapshot.state
      : { loading: false };
  const isLoadingMore = paginationState.loading;
  const paginationError = paginationState.error ?? null;
  const paginationGenerationRef = useRef(0);
  const paginationRequestRef = useRef<PaginationRequest | null>(null);
  const userCursorHistoryRef = useRef(new Set<string>());
  const selectedUserSelection =
    authorityReady && userSelection?.pairKey === requestPair
      ? userSelection
      : null;
  const selectedUser = selectedUserSelection?.user ?? null;
  const canGrant = authority.hasPermission("role.grant");
  const canManageMembership = authority.hasPermission("membership.manage");
  const [lifecycleSelection, setLifecycleSelection] =
    useState<LifecycleSelection | null>(null);
  const selectedLifecycle =
    authorityReady && lifecycleSelection?.pairKey === requestPair
      ? lifecycleSelection
      : null;

  useEffect(() => {
    if (authorityReady) {
      return;
    }
    userSelectionGenerationRef.current += 1;
    setUserSelection(null);
    setLifecycleSelection(null);
    paginationGenerationRef.current += 1;
    paginationRequestRef.current?.controller.abort();
    paginationRequestRef.current = null;
    userCursorHistoryRef.current = new Set();
    setPaginationSnapshot({
      pairKey: requestPair,
      state: { loading: false },
    });
    setListSnapshot({ pairKey: requestPair, state: initialListState });
  }, [
    initialListState,
    authority.message,
    authority.status,
    authorityReady,
    canRead,
    requestPair,
    tenantId,
  ]);

  useEffect(() => {
    paginationGenerationRef.current += 1;
    paginationRequestRef.current?.controller.abort();
    paginationRequestRef.current = null;
    userCursorHistoryRef.current = new Set();
    setPaginationSnapshot({
      pairKey: requestPair,
      state: { loading: false },
    });
    if (!tenantId || authority.status !== "ready" || !canRead) {
      setListSnapshot({
        pairKey: requestPair,
        state: initialListState,
      });
      return undefined;
    }
    const controller = new AbortController();
    setListSnapshot({ pairKey: requestPair, state: { kind: "loading" } });

    void api
      .listTenantUsers(tenantId, undefined, controller.signal)
      .then((page) => {
        if (
          !controller.signal.aborted &&
          requestPairRef.current === requestPair &&
          authorityReadyRef.current
        ) {
          assertTenantUsers(page.items, tenantId);
          if (page.nextCursor) {
            userCursorHistoryRef.current.add(page.nextCursor);
          }
          setListSnapshot({
            pairKey: requestPair,
            state: {
              items: page.items,
              kind: "ready",
              ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
            },
          });
        }
      })
      .catch((caught: unknown) => {
        if (
          controller.signal.aborted ||
          requestPairRef.current !== requestPair ||
          !authorityReadyRef.current
        ) {
          return;
        }
        if (caught instanceof PhaseTwoApiError && caught.status === 401) {
          clearSession(session.id);
          return;
        }
        if (caught instanceof PhaseTwoApiError && caught.status === 403) {
          setListSnapshot({
            pairKey: requestPair,
            state: { kind: "forbidden" },
          });
          return;
        }
        setListSnapshot({
          pairKey: requestPair,
          state: {
            kind: "error",
            message: describePhaseTwoError(
              caught,
              "The tenant user inventory could not be loaded.",
            ),
          },
        });
      });

    return () => controller.abort();
  }, [
    initialListState,
    api,
    authority.message,
    authority.status,
    canRead,
    clearSession,
    loadAttempt,
    requestPair,
    session.id,
    tenantId,
  ]);

  useEffect(() => {
    userSelectionGenerationRef.current += 1;
    setUserSelection(null);
    return () => {
      userSelectionGenerationRef.current += 1;
      paginationGenerationRef.current += 1;
      paginationRequestRef.current?.controller.abort();
      paginationRequestRef.current = null;
    };
  }, [requestPair]);

  useEffect(() => {
    if (!selectedLifecycle || listState.kind !== "ready") {
      return;
    }
    const current = listState.items.find(
      (item) => item.membershipId === selectedLifecycle.user.membershipId,
    );
    if (
      current &&
      (current.lifecycleRevision !== selectedLifecycle.user.lifecycleRevision ||
        current.etag !== selectedLifecycle.user.etag)
    ) {
      setLifecycleSelection({ pairKey: requestPair, user: current });
    }
  }, [listState, requestPair, selectedLifecycle]);

  function openUserAccess(user: TenantUserSummaryView): void {
    if (!authorityReadyRef.current) {
      return;
    }
    const generation = userSelectionGenerationRef.current + 1;
    userSelectionGenerationRef.current = generation;
    setUserSelection({ generation, pairKey: requestPair, user });
  }

  function closeUserAccess(): void {
    userSelectionGenerationRef.current += 1;
    setUserSelection(null);
  }

  function openMembershipLifecycle(user: TenantUserSummaryView): void {
    if (!authorityReadyRef.current || !canManageMembership) {
      return;
    }
    closeUserAccess();
    setLifecycleSelection({ pairKey: requestPair, user });
  }

  function applyMembershipLifecycle(
    current: TenantUserSummaryView,
    result: Pick<
      TenantUserSummaryView,
      "etag" | "lifecycleRevision" | "membershipStatus" | "updatedAt"
    >,
  ): void {
    setListSnapshot((snapshot) => {
      if (snapshot.pairKey !== requestPair || snapshot.state.kind !== "ready") {
        return snapshot;
      }
      return {
        pairKey: snapshot.pairKey,
        state: {
          ...snapshot.state,
          items: snapshot.state.items.map((item) =>
            item.membershipId === current.membershipId
              ? { ...item, ...result }
              : item,
          ),
        },
      };
    });
    setLifecycleSelection(null);
    authority.reload();
  }

  async function loadMore(): Promise<void> {
    if (
      !tenantId ||
      !authorityReadyRef.current ||
      listState.kind !== "ready" ||
      !listState.nextCursor ||
      isLoadingMore
    ) {
      return;
    }
    const cursor = listState.nextCursor;
    const expectedPair = requestPair;
    paginationRequestRef.current?.controller.abort();
    const controller = new AbortController();
    const generation = paginationGenerationRef.current + 1;
    paginationGenerationRef.current = generation;
    paginationRequestRef.current = {
      controller,
      cursor,
      generation,
      pairKey: expectedPair,
    };
    setPaginationSnapshot({
      pairKey: expectedPair,
      state: { loading: true },
    });
    try {
      const page = await api.listTenantUsers(
        tenantId,
        cursor,
        controller.signal,
      );
      if (
        requestPairRef.current !== expectedPair ||
        !authorityReadyRef.current ||
        !isCurrentPaginationRequest(
          paginationRequestRef.current,
          expectedPair,
          cursor,
          generation,
        )
      ) {
        return;
      }
      assertTenantUsers(page.items, tenantId);
      if (
        page.nextCursor &&
        (page.nextCursor === cursor ||
          userCursorHistoryRef.current.has(page.nextCursor))
      ) {
        throw new Error("The user cursor did not advance.");
      }
      if (page.nextCursor) {
        userCursorHistoryRef.current.add(page.nextCursor);
      }
      setListSnapshot((current) => {
        if (
          current.pairKey !== expectedPair ||
          current.state.kind !== "ready" ||
          current.state.nextCursor !== cursor
        ) {
          return current;
        }
        return {
          pairKey: expectedPair,
          state: {
            items: mergeTenantUsers(current.state.items, page.items),
            kind: "ready",
            ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
          },
        };
      });
    } catch (caught) {
      if (
        requestPairRef.current !== expectedPair ||
        !authorityReadyRef.current ||
        !isCurrentPaginationRequest(
          paginationRequestRef.current,
          expectedPair,
          cursor,
          generation,
        )
      ) {
        return;
      }
      if (caught instanceof PhaseTwoApiError && caught.status === 401) {
        clearSession(session.id);
        return;
      }
      setPaginationSnapshot({
        pairKey: expectedPair,
        state: {
          error: describePhaseTwoError(
            caught,
            "More tenant users could not be loaded.",
          ),
          loading: true,
        },
      });
    } finally {
      if (
        requestPairRef.current === expectedPair &&
        authorityReadyRef.current &&
        isCurrentPaginationRequest(
          paginationRequestRef.current,
          expectedPair,
          cursor,
          generation,
        )
      ) {
        paginationRequestRef.current = null;
        setPaginationSnapshot((current) =>
          current.pairKey === expectedPair
            ? {
                pairKey: expectedPair,
                state: { ...current.state, loading: false },
              }
            : current,
        );
      }
    }
  }

  if (listState.kind === "forbidden") {
    return {
      kind: "content" as const,
      content: <ServerDenied resource="the tenant user inventory" />,
    };
  }

  if (listState.kind === "inactive") {
    return {
      kind: "content" as const,
      content: (
        <TenantRequiredPage
          label="Tenant authorization"
          title="Select a tenant to inspect users."
        >
          User administration always requires an explicit tenant path.
        </TenantRequiredPage>
      ),
    };
  }

  return {
    kind: "ready" as const,
    data: {
      api,
      applyMembershipLifecycle,
      authority,
      authorityReadyRef,
      canGrant,
      canManageMembership,
      clearSession,
      closeUserAccess,
      isLoadingMore,
      listState,
      loadMore,
      openMembershipLifecycle,
      openUserAccess,
      paginationError,
      requestPair,
      requestPairRef,
      selectedLifecycle,
      selectedUser,
      selectedUserSelection,
      session,
      setLifecycleSelection,
      setLoadAttempt,
      tenantId,
    },
  };
}

function TenantUsersPageView({
  model,
}: {
  model: Extract<
    ReturnType<typeof useTenantUsersPageModel>,
    { kind: "ready" }
  >["data"];
}): React.JSX.Element {
  return <UserWorkspace model={model} />;
}

function MembershipLifecycleDialog({
  api,
  csrfToken,
  isCurrent,
  onCompleted,
  onOpenChange,
  onStale,
  tenantId,
  user,
}: {
  api: PhaseTwoApi;
  csrfToken: string;
  isCurrent: () => boolean;
  onCompleted: (receipt: TenantMembershipLifecycleReceiptView) => void;
  onOpenChange: (open: boolean) => void;
  onStale: () => void;
  tenantId: string;
  user: TenantUserSummaryView;
}): React.JSX.Element {
  const { clearSession, session } = useSession();
  const reasonId = useId();
  const [reason, setReason] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const idempotencyBindingRef = useRef<{
    fingerprint: string;
    key: string;
  } | null>(null);
  const targetStatus =
    user.membershipStatus === "active" ? "suspended" : "active";
  const suspending = targetStatus === "suspended";
  const action = suspending ? "Suspend" : "Reactivate";

  async function submit(
    event: React.FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault();
    const parsed = lifecycleReasonSchema.safeParse(reason);
    if (!parsed.success) {
      setError(
        parsed.error.issues[0]?.message ?? "Enter an administrative reason.",
      );
      return;
    }
    if (!isCurrent()) {
      return;
    }
    const payload = {
      expectedRevision: user.lifecycleRevision,
      reason: parsed.data,
      targetStatus,
      tenantId,
      userId: user.user.id,
    };
    setError(null);
    setSaving(true);
    try {
      const receipt = await api.changeTenantMembershipLifecycle(
        csrfToken,
        tenantId,
        user.user.id,
        targetStatus,
        user,
        idempotencyKeyForPayload(idempotencyBindingRef, payload),
        parsed.data,
      );
      if (
        isCurrent() &&
        isPayloadBoundToIdempotencyKey(idempotencyBindingRef, payload)
      ) {
        onCompleted(receipt);
      }
    } catch (caught) {
      if (!isCurrent()) {
        return;
      }
      if (caught instanceof PhaseTwoApiError && caught.status === 401) {
        clearSession(session.id);
        return;
      }
      if (caught instanceof PhaseTwoApiError && caught.status === 412) {
        onStale();
        setError(
          "This membership changed on the server. The current row is being reloaded; your reason is preserved for an exact retry.",
        );
        return;
      }
      setError(
        describePhaseTwoError(
          caught,
          `The membership was not ${suspending ? "suspended" : "reactivated"}. Your reason is preserved.`,
        ),
      );
    } finally {
      if (isCurrent()) {
        // react-doctor-disable-next-line no-loading-flag-reset-outside-finally -- The owning request clears this flag in finally; the generation guard protects newer requests.
        setSaving(false);
      }
    }
  }

  return (
    <Dialog open onOpenChange={onOpenChange}>
      <DialogContent>
        <form className="grid gap-4" onSubmit={(event) => void submit(event)}>
          <DialogHeader>
            <DialogTitle>{action} tenant membership</DialogTitle>
            <DialogDescription>
              {action} access for {user.user.displayName} ({user.user.email}).
              This action is tenant-scoped and requires an exact current
              membership revision.
            </DialogDescription>
          </DialogHeader>

          <Alert variant={suspending ? "destructive" : "default"}>
            {suspending ? (
              <Ban aria-hidden="true" />
            ) : (
              <RotateCcw aria-hidden="true" />
            )}
            <AlertTitle>
              {suspending
                ? "Tenant access and in-flight authentication will be revoked"
                : "Only membership access will be restored"}
            </AlertTitle>
            <AlertDescription>
              {suspending
                ? "Active sessions and pending continuations for this user in this tenant will be revoked. Other tenants and platform sessions are not affected."
                : "Previously revoked sessions and continuations remain revoked. The user must authenticate again to receive new tenant authority."}
            </AlertDescription>
          </Alert>

          {error ? <FocusedError message={error} /> : null}

          <div className="grid gap-2">
            <label htmlFor={reasonId}>Administrative reason</label>
            <Textarea
              id={reasonId}
              autoFocus
              maxLength={2048}
              rows={4}
              value={reason}
              aria-describedby={`${reasonId}-help`}
              onChange={(event) => {
                setReason(event.currentTarget.value);
                setError(null);
              }}
              placeholder={
                suspending
                  ? "Example: Access paused during offboarding review"
                  : "Example: Access review completed and approved"
              }
            />
            <small id={`${reasonId}-help`}>
              Required in the immutable audit record. Do not include passwords,
              tokens, assertions, or recovery codes.
            </small>
          </div>

          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              disabled={saving}
              onClick={() => onOpenChange(false)}
            >
              Cancel
            </Button>
            <Button
              type="submit"
              variant={suspending ? "destructive" : "default"}
              disabled={saving}
            >
              {suspending ? (
                <Ban aria-hidden="true" />
              ) : (
                <RotateCcw aria-hidden="true" />
              )}
              {saving
                ? suspending
                  ? "Suspending…"
                  : "Reactivating…"
                : `${action} ${user.user.displayName}`}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function UserAccessDialog(props: {
  api: PhaseTwoApi;
  canGrant: boolean;
  csrfToken: string;
  delegation: readonly EffectiveTenantDelegationView[];
  effectiveGrants: readonly EffectiveTenantRoleGrantView[];
  onAuthorityChanged: () => void;
  onOpenChange: (open: boolean) => void;
  pairKey: string;
  tenantId: string;
  user: TenantUserSummaryView;
}): React.JSX.Element {
  const model = useUserAccessDialogModel(props);
  return <UserAccessDialogView model={model.data} />;
}

function useUserAccessDialogModel({
  api,
  canGrant,
  csrfToken,
  delegation,
  effectiveGrants,
  onAuthorityChanged,
  onOpenChange,
  pairKey,
  tenantId,
  user,
}: {
  api: PhaseTwoApi;
  canGrant: boolean;
  csrfToken: string;
  delegation: readonly EffectiveTenantDelegationView[];
  effectiveGrants: readonly EffectiveTenantRoleGrantView[];
  onAuthorityChanged: () => void;
  onOpenChange: (open: boolean) => void;
  pairKey: string;
  tenantId: string;
  user: TenantUserSummaryView;
}) {
  const { clearSession, session } = useSession();
  const [loadRevision, setLoadRevision] = useState(0);
  const dialogKey = JSON.stringify([pairKey, user.user.id]);
  const grantRequestKey = JSON.stringify([dialogKey, loadRevision]);
  const [grantSnapshot, setGrantSnapshot] = useState<
    PairSnapshot<GrantListState>
  >(() => ({ pairKey: grantRequestKey, state: { kind: "loading" } }));
  const grantSnapshotRef = useRef(grantSnapshot);
  const grantState =
    grantSnapshot.pairKey === grantRequestKey
      ? grantSnapshot.state
      : { kind: "loading" as const };
  const [grantingKey, setGrantingKey] = useState<string | null>(null);
  const granting = grantingKey === dialogKey;
  const grantRequestRef = useRef(grantRequestKey);
  useLayoutEffect(() => {
    grantRequestRef.current = grantRequestKey;
  });
  const grantLoadGenerationRef = useRef(0);
  const grantPaginationGenerationRef = useRef(0);
  const grantPaginationRequestRef = useRef<PaginationRequest | null>(null);
  const grantCursorHistoryRef = useRef(new Set<string>());
  const grantRefreshRequestsRef = useRef(
    new Map<string, GrantRefreshRequest>(),
  );
  const dialogMountedRef = useRef(false);
  const [grantPaginationSnapshot, setGrantPaginationSnapshot] = useState<
    PairSnapshot<PaginationState>
  >(() => ({ pairKey: grantRequestKey, state: { loading: false } }));
  const grantPaginationState =
    grantPaginationSnapshot.pairKey === grantRequestKey
      ? grantPaginationSnapshot.state
      : { loading: false };
  const [revokeDrafts, setRevokeDrafts] = useState<
    Readonly<Record<string, RevokeDraft>>
  >({});

  function commitGrantSnapshot(next: PairSnapshot<GrantListState>): void {
    grantSnapshotRef.current = next;
    // react-doctor-disable-next-line react-doctor/no-derived-state -- next is an asynchronously loaded or refreshed grant snapshot, not a prop-derived value.
    setGrantSnapshot(next);
  }

  function updateRevokeDraft(
    grantId: string,
    update: (draft: RevokeDraft) => RevokeDraft,
  ): void {
    setRevokeDrafts((current) => ({
      ...current,
      [grantId]: update(current[grantId] ?? emptyRevokeDraft),
    }));
  }

  function clearRevokeDraft(grantId: string): void {
    setRevokeDrafts((current) => {
      if (!(grantId in current)) {
        return current;
      }
      const next = { ...current };
      delete next[grantId];
      return next;
    });
  }

  useEffect(() => {
    dialogMountedRef.current = true;
    return () => {
      dialogMountedRef.current = false;
    };
  }, []);

  // react-doctor-disable-next-line react-doctor/no-derived-state-effect -- This cancellable effect loads grant history from the API; server results and freshness cannot be derived during rendering.
  useEffect(() => {
    const generation = grantLoadGenerationRef.current + 1;
    grantLoadGenerationRef.current = generation;
    grantPaginationGenerationRef.current += 1;
    grantPaginationRequestRef.current?.controller.abort();
    grantPaginationRequestRef.current = null;
    grantCursorHistoryRef.current = new Set();
    for (const request of grantRefreshRequestsRef.current.values()) {
      request.controller.abort();
    }
    grantRefreshRequestsRef.current.clear();
    setGrantPaginationSnapshot({
      pairKey: grantRequestKey,
      state: { loading: false },
    });
    const controller = new AbortController();
    commitGrantSnapshot({
      pairKey: grantRequestKey,
      state: { kind: "loading" },
    });
    void api
      .listUserRoleGrants(tenantId, user.user.id, {
        includeRevoked: true,
        signal: controller.signal,
      })
      .then((page) => {
        if (
          !controller.signal.aborted &&
          grantRequestRef.current === grantRequestKey &&
          grantLoadGenerationRef.current === generation
        ) {
          assertDirectGrants(page.items, tenantId, user.user.id);
          if (page.nextCursor) {
            grantCursorHistoryRef.current.add(page.nextCursor);
          }
          commitGrantSnapshot({
            pairKey: grantRequestKey,
            state: {
              items: mergeDirectGrantEntries([], page.items, undefined),
              kind: "ready",
              ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
            },
          });
        }
      })
      .catch((caught: unknown) => {
        if (
          controller.signal.aborted ||
          grantRequestRef.current !== grantRequestKey ||
          grantLoadGenerationRef.current !== generation
        ) {
          return;
        }
        if (caught instanceof PhaseTwoApiError && caught.status === 401) {
          clearSession(session.id);
          return;
        }
        if (caught instanceof PhaseTwoApiError && caught.status === 403) {
          commitGrantSnapshot({
            pairKey: grantRequestKey,
            state: { kind: "forbidden" },
          });
          return;
        }
        commitGrantSnapshot({
          pairKey: grantRequestKey,
          state: {
            kind: "error",
            message: describePhaseTwoError(
              caught,
              "Direct role grants could not be loaded.",
            ),
          },
        });
      });
    return () => {
      controller.abort();
      grantPaginationGenerationRef.current += 1;
      grantPaginationRequestRef.current?.controller.abort();
      grantPaginationRequestRef.current = null;
      for (const request of grantRefreshRequestsRef.current.values()) {
        request.controller.abort();
      }
      grantRefreshRequestsRef.current.clear();
    };
  }, [api, clearSession, grantRequestKey, session.id, tenantId, user.user.id]);

  async function loadMoreGrantHistory(): Promise<void> {
    if (
      grantState.kind !== "ready" ||
      !grantState.nextCursor ||
      grantPaginationState.loading
    ) {
      return;
    }
    const cursor = grantState.nextCursor;
    const expectedRequestKey = grantRequestKey;
    grantPaginationRequestRef.current?.controller.abort();
    const controller = new AbortController();
    const generation = grantPaginationGenerationRef.current + 1;
    grantPaginationGenerationRef.current = generation;
    grantPaginationRequestRef.current = {
      controller,
      cursor,
      generation,
      pairKey: expectedRequestKey,
    };
    setGrantPaginationSnapshot({
      pairKey: expectedRequestKey,
      state: { loading: true },
    });
    try {
      const page = await api.listUserRoleGrants(tenantId, user.user.id, {
        after: cursor,
        includeRevoked: true,
        signal: controller.signal,
      });
      if (
        grantRequestRef.current !== expectedRequestKey ||
        !isCurrentPaginationRequest(
          grantPaginationRequestRef.current,
          expectedRequestKey,
          cursor,
          generation,
        )
      ) {
        return;
      }
      assertDirectGrants(page.items, tenantId, user.user.id);
      if (
        page.nextCursor &&
        (page.nextCursor === cursor ||
          grantCursorHistoryRef.current.has(page.nextCursor))
      ) {
        throw new Error("The role grant cursor did not advance.");
      }
      if (page.nextCursor) {
        grantCursorHistoryRef.current.add(page.nextCursor);
      }
      const current = grantSnapshotRef.current;
      if (
        current.pairKey !== expectedRequestKey ||
        current.state.kind !== "ready" ||
        current.state.nextCursor !== cursor
      ) {
        return;
      }
      commitGrantSnapshot({
        pairKey: expectedRequestKey,
        state: {
          items: mergeDirectGrantEntries(
            current.state.items,
            page.items,
            cursor,
          ),
          kind: "ready",
          ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
        },
      });
    } catch (caught) {
      if (
        grantRequestRef.current !== expectedRequestKey ||
        !isCurrentPaginationRequest(
          grantPaginationRequestRef.current,
          expectedRequestKey,
          cursor,
          generation,
        )
      ) {
        return;
      }
      if (caught instanceof PhaseTwoApiError && caught.status === 401) {
        clearSession(session.id);
        return;
      }
      setGrantPaginationSnapshot({
        pairKey: expectedRequestKey,
        state: {
          error: describePhaseTwoError(
            caught,
            "More direct role grant history could not be loaded.",
          ),
          loading: true,
        },
      });
    } finally {
      if (
        grantRequestRef.current === expectedRequestKey &&
        isCurrentPaginationRequest(
          grantPaginationRequestRef.current,
          expectedRequestKey,
          cursor,
          generation,
        )
      ) {
        grantPaginationRequestRef.current = null;
        setGrantPaginationSnapshot((current) =>
          current.pairKey === expectedRequestKey
            ? {
                pairKey: expectedRequestKey,
                state: { ...current.state, loading: false },
              }
            : current,
        );
      }
    }
  }

  function isCurrentDialogRequest(expectedRequestKey: string): boolean {
    return (
      dialogMountedRef.current && grantRequestRef.current === expectedRequestKey
    );
  }

  async function refreshDirectGrant(
    rejectedEntry: DirectGrantEntry,
  ): Promise<DirectUserRoleGrantView | null> {
    if (!dialogMountedRef.current) {
      return null;
    }
    const expectedRequestKey = grantRequestRef.current;
    const grantId = rejectedEntry.grant.id;
    const loadedEntry = findDirectGrantEntry(
      grantSnapshotRef.current,
      expectedRequestKey,
      grantId,
    );
    let recoveryEntry = rejectedEntry;
    if (loadedEntry) {
      if (loadedEntry.grant.version > rejectedEntry.grant.version) {
        return loadedEntry.grant;
      }
      if (loadedEntry.grant.version === rejectedEntry.grant.version) {
        recoveryEntry = loadedEntry;
      }
    }
    grantRefreshRequestsRef.current.get(grantId)?.controller.abort();
    const request: GrantRefreshRequest = {
      controller: new AbortController(),
    };
    grantRefreshRequestsRef.current.set(grantId, request);
    let cursor = recoveryEntry.originCursor;
    const seenCursors = new Set(cursor ? [cursor] : []);

    try {
      for (let pageNumber = 0; pageNumber < 2; pageNumber += 1) {
        // oxlint-disable-next-line no-await-in-loop -- Exact-edge recovery follows at most one advancing cursor from the originating page.
        const page = await api.listUserRoleGrants(tenantId, user.user.id, {
          ...(cursor ? { after: cursor } : {}),
          includeRevoked: true,
          signal: request.controller.signal,
        });
        if (
          !isCurrentDialogRequest(expectedRequestKey) ||
          grantRefreshRequestsRef.current.get(grantId) !== request
        ) {
          return null;
        }
        assertDirectGrants(page.items, tenantId, user.user.id);
        const matchingGrants = page.items.filter((item) => item.id === grantId);
        if (matchingGrants.length > 0) {
          const refreshedEntry = mergeDirectGrantEntries(
            [],
            matchingGrants,
            cursor,
          )[0];
          if (
            refreshedEntry &&
            directGrantRefreshAdvanced(rejectedEntry, refreshedEntry)
          ) {
            const current = grantSnapshotRef.current;
            if (
              current.pairKey !== expectedRequestKey ||
              current.state.kind !== "ready"
            ) {
              return null;
            }
            const merged = mergeRefreshedDirectGrantEntry(
              current.state.items,
              rejectedEntry,
              refreshedEntry,
            );
            if (merged.items !== current.state.items) {
              commitGrantSnapshot({
                pairKey: expectedRequestKey,
                state: { ...current.state, items: merged.items },
              });
            }
            return merged.entry.grant;
          }
        }
        if (!page.nextCursor) {
          break;
        }
        if (page.nextCursor === cursor || seenCursors.has(page.nextCursor)) {
          throw new Error("The role grant cursor did not advance.");
        }
        seenCursors.add(page.nextCursor);
        cursor = page.nextCursor;
      }
      throw new Error(
        `The exact grant refresh did not return a different ETag at version ${rejectedEntry.grant.version} or a higher version on its originating history page or the next page.`,
      );
    } finally {
      if (grantRefreshRequestsRef.current.get(grantId) === request) {
        grantRefreshRequestsRef.current.delete(grantId);
      }
    }
  }

  return {
    kind: "ready" as const,
    data: {
      api,
      canGrant,
      clearRevokeDraft,
      csrfToken,
      delegation,
      dialogKey,
      dialogMountedRef,
      effectiveGrants,
      grantPaginationState,
      grantRequestKey,
      grantState,
      granting,
      isCurrentDialogRequest,
      loadMoreGrantHistory,
      onAuthorityChanged,
      onOpenChange,
      refreshDirectGrant,
      revokeDrafts,
      setGrantingKey,
      setLoadRevision,
      tenantId,
      updateRevokeDraft,
      user,
    },
  };
}

function UserAccessDialogView({
  model,
}: {
  model: Extract<
    ReturnType<typeof useUserAccessDialogModel>,
    { kind: "ready" }
  >["data"];
}): React.JSX.Element {
  return <UserAccessDialogContent model={model} />;
}

export function InheritedGroupPaths({
  grants,
}: {
  grants: readonly EffectiveTenantRoleGrantView[];
}): React.JSX.Element {
  return (
    <section
      className="inherited-group-paths"
      aria-labelledby="inherited-group-paths-title"
    >
      <div>
        <p className="section-label">Inherited authority</p>
        <h3 id="inherited-group-paths-title">Security-group access paths</h3>
        <p>
          These are live paths for the signed-in user. Each membership edge and
          role edge keeps an independent source owner and lifetime.
        </p>
      </div>
      {grants.map((grant) => {
        if (grant.path.pathType !== "group") {
          return null;
        }
        const groupPath = grant.path.group;
        return (
          <article
            className="inherited-group-path"
            key={effectiveAuthorityPathKey(grant)}
          >
            <header>
              <span>
                <strong>{grant.roleName}</strong>
                <small>{grant.roleKey}</small>
              </span>
              <Badge variant="secondary">Active path</Badge>
            </header>
            <AccessPathRail group={groupPath.group} />
            <div className="inherited-edge-provenance">
              <div>
                <small>Membership edge source</small>
                <strong>
                  {formatStatus(groupPath.membershipEdge.provenance.sourceKind)}
                </strong>
                <code>{groupPath.membershipEdge.provenance.sourceId}</code>
                <p>{groupPath.membershipEdge.provenance.reason}</p>
              </div>
              <div>
                <small>Role edge source</small>
                <strong>
                  {formatStatus(groupPath.roleGrantEdge.provenance.sourceKind)}
                </strong>
                <code>{groupPath.roleGrantEdge.provenance.sourceId}</code>
                <p>{groupPath.roleGrantEdge.provenance.reason}</p>
              </div>
            </div>
            <p className="effective-path-expiry">
              Complete path expiry:{" "}
              {grant.effectiveExpiresAt
                ? formatTimestamp(grant.effectiveExpiresAt)
                : "No scheduled expiry"}
            </p>
          </article>
        );
      })}
    </section>
  );
}

function DirectGrantCard(props: {
  api: PhaseTwoApi;
  canGrant: boolean;
  csrfToken: string;
  draft: RevokeDraft;
  entry: DirectGrantEntry;
  isDialogActive: () => boolean;
  isGrantViewCurrent: () => boolean;
  onCancel: () => void;
  onDraftChange: (update: (draft: RevokeDraft) => RevokeDraft) => void;
  onRefreshStale: (
    rejectedEntry: DirectGrantEntry,
  ) => Promise<DirectUserRoleGrantView | null>;
  onRevoked: () => void;
  tenantId: string;
  userActive: boolean;
  userMembershipStatus: TenantUserSummaryView["membershipStatus"];
}): React.JSX.Element {
  const model = useDirectGrantCardModel(props);
  return <DirectGrantCardView model={model.data} />;
}

function useDirectGrantCardModel({
  api,
  canGrant,
  csrfToken,
  draft,
  entry,
  isDialogActive,
  isGrantViewCurrent,
  onCancel,
  onDraftChange,
  onRefreshStale,
  onRevoked,
  tenantId,
  userActive,
  userMembershipStatus,
}: {
  api: PhaseTwoApi;
  canGrant: boolean;
  csrfToken: string;
  draft: RevokeDraft;
  entry: DirectGrantEntry;
  isDialogActive: () => boolean;
  isGrantViewCurrent: () => boolean;
  onCancel: () => void;
  onDraftChange: (update: (draft: RevokeDraft) => RevokeDraft) => void;
  onRefreshStale: (
    rejectedEntry: DirectGrantEntry,
  ) => Promise<DirectUserRoleGrantView | null>;
  onRevoked: () => void;
  tenantId: string;
  userActive: boolean;
  userMembershipStatus: TenantUserSummaryView["membershipStatus"];
}) {
  const { clearSession, session } = useSession();
  const id = useId();
  const grant = entry.grant;
  const isSaving = draft.saving;
  const staleRefreshState = draft.refresh.kind;
  const rejectedRefreshEntry =
    draft.refresh.kind === "idle" ? null : draft.refresh.entry;
  const expiryReached = useDeadlineReached(
    grant.state === "active" ? grant.provenance.expiresAt : undefined,
  );
  const roleTarget = `${grant.role.name} (${grant.role.key})`;
  const authorityBlockers = directGrantAuthorityBlockers(
    grant,
    userMembershipStatus,
    userActive,
    expiryReached,
  );
  const authorityBlocker = joinAuthorityBlockers(authorityBlockers);

  async function refreshStaleGrant(
    rejectedEntry: DirectGrantEntry,
  ): Promise<void> {
    if (!isGrantViewCurrent()) {
      return;
    }
    onDraftChange((current) => ({
      ...current,
      refresh: { entry: rejectedEntry, kind: "refreshing" },
    }));
    try {
      const refreshedGrant = await onRefreshStale(rejectedEntry);
      if (!isDialogActive()) {
        return;
      }
      if (!isGrantViewCurrent() || !refreshedGrant) {
        onDraftChange((current) => ({
          ...current,
          error:
            "The grant list changed while the exact grant was being reloaded. Your reason is preserved; retry the refresh before revoking.",
          notice: null,
          open: true,
          refresh: { entry: rejectedEntry, kind: "required" },
        }));
        return;
      }
      const terminalNotice = directGrantNonRevocableNotice(refreshedGrant);
      if (terminalNotice) {
        onDraftChange(() => ({
          ...emptyRevokeDraft,
          notice: terminalNotice,
        }));
        return;
      }
      onDraftChange((current) => ({
        ...current,
        error:
          "This grant changed on the server. We reloaded the current grant; your reason is preserved. Review it and retry with the latest version.",
        notice: null,
        open: true,
        refresh: { kind: "idle" },
      }));
    } catch (caught) {
      if (!isDialogActive()) {
        return;
      }
      if (caught instanceof PhaseTwoApiError && caught.status === 401) {
        clearSession(session.id);
        return;
      }
      const detail = describePhaseTwoError(
        caught,
        "The refresh request failed.",
      );
      onDraftChange((current) => ({
        ...current,
        error: `The current grant could not be reloaded. Your reason is preserved; retry the refresh before revoking. ${detail}`,
        notice: null,
        open: true,
        refresh: { entry: rejectedEntry, kind: "required" },
      }));
    }
  }

  async function revoke(): Promise<void> {
    const parsed = reasonSchema.safeParse(draft.reason);
    if (!parsed.success) {
      onDraftChange((current) => ({
        ...current,
        error: parsed.error.issues[0]?.message ?? "Enter a reason.",
        notice: null,
      }));
      return;
    }
    if (!isGrantViewCurrent()) {
      return;
    }
    onDraftChange((current) => ({
      ...current,
      error: null,
      notice: null,
      saving: true,
    }));
    let completed = false;
    try {
      await api.revokeRoleGrant(csrfToken, tenantId, grant.id, grant.etag, {
        reason: parsed.data,
      });
      if (!isDialogActive()) {
        return;
      }
      completed = true;
      onRevoked();
    } catch (caught) {
      if (!isDialogActive()) {
        return;
      }
      if (caught instanceof PhaseTwoApiError && caught.status === 401) {
        clearSession(session.id);
        return;
      }
      const stale = caught instanceof PhaseTwoApiError && caught.status === 412;
      const canRefreshCurrentView = stale && isGrantViewCurrent();
      onDraftChange((current) => ({
        ...current,
        error: stale
          ? canRefreshCurrentView
            ? "This grant changed on the server. Reloading the exact grant now; your reason is preserved."
            : "The grant list changed after this revoke began. Your reason is preserved; retry the exact grant refresh before revoking."
          : describePhaseTwoError(
              caught,
              "The grant was not revoked. Your reason is preserved.",
            ),
        notice: null,
        open: true,
        ...(stale
          ? {
              refresh: {
                entry,
                kind: canRefreshCurrentView
                  ? ("refreshing" as const)
                  : ("required" as const),
              },
            }
          : {}),
      }));
      if (canRefreshCurrentView) {
        await refreshStaleGrant(entry);
      }
    } finally {
      if (!completed && isDialogActive()) {
        onDraftChange((current) => ({ ...current, saving: false }));
      }
    }
  }

  return {
    kind: "ready" as const,
    data: {
      authorityBlocker,
      canGrant,
      draft,
      grant,
      id,
      isSaving,
      onCancel,
      onDraftChange,
      refreshStaleGrant,
      rejectedRefreshEntry,
      revoke,
      roleTarget,
      staleRefreshState,
      userActive,
      userMembershipStatus,
    },
  };
}

function DirectGrantCardView({
  model,
}: {
  model: Extract<
    ReturnType<typeof useDirectGrantCardModel>,
    { kind: "ready" }
  >["data"];
}): React.JSX.Element {
  return <DirectGrantDetails model={model} />;
}

function useDeadlineReached(value: string | undefined): boolean {
  const [, setRevision] = useState(0);
  const deadline = value ? parseRfc3339Instant(value) : undefined;

  useEffect(() => {
    if (deadline === undefined || hasInstantReached(deadline)) {
      return undefined;
    }
    let active = true;
    let timeout: ReturnType<typeof setTimeout> | undefined;
    const schedule = (): void => {
      if (!active) {
        return;
      }
      const remainingNanoseconds = deadline - currentInstant();
      if (remainingNanoseconds <= 0n) {
        setRevision((revision) => revision + 1);
        return;
      }
      const remainingMilliseconds = Number(
        (remainingNanoseconds + 999_999n) / 1_000_000n,
      );
      timeout = setTimeout(
        schedule,
        Math.min(remainingMilliseconds, maximumTimerDelay),
      );
    };
    schedule();
    return () => {
      active = false;
      if (timeout !== undefined) {
        clearTimeout(timeout);
      }
    };
  }, [deadline]);

  return deadline !== undefined && hasInstantReached(deadline);
}

function directGrantNonRevocableNotice(
  grant: DirectUserRoleGrantView,
): string | null {
  if (directGrantIsRevocable(grant)) {
    return null;
  }
  if (grant.state === "revoked") {
    return "This grant is already revoked on the server. No further revoke is needed.";
  }
  return `The current grant is not managed by the authorization API (source: ${formatStatus(grant.provenance.sourceKind)}) and cannot be revoked here.`;
}

function directGrantIsRevocable(grant: DirectUserRoleGrantView): boolean {
  return (
    grant.state !== "revoked" &&
    isManagedByAuthorizationApi(grant.managedByAuthorizationApi)
  );
}

function isManagedByAuthorizationApi(value: unknown): value is true {
  return value === true;
}

function directGrantAuthorityBlockers(
  grant: DirectUserRoleGrantView,
  membershipStatus: TenantUserSummaryView["membershipStatus"],
  userActive: boolean,
  expiryReached: boolean,
): readonly string[] {
  const blockers: string[] = [];
  if (grant.state !== "active") {
    blockers.push(`the edge is ${formatStatus(grant.state)}`);
  } else if (expiryReached) {
    blockers.push("the edge has expired");
  }
  if (grant.provenance.retiredAt) {
    blockers.push("its source is retired");
  }
  if (grant.role.archived) {
    blockers.push("its role is archived");
  }
  if (membershipStatus !== "active") {
    blockers.push(`the tenant membership is ${formatStatus(membershipStatus)}`);
  }
  if (!userActive) {
    blockers.push("the user is disabled");
  }
  return blockers;
}

function joinAuthorityBlockers(blockers: readonly string[]): string | null {
  if (blockers.length === 0) {
    return null;
  }
  if (blockers.length === 1) {
    return blockers[0] ?? null;
  }
  return `${blockers.slice(0, -1).join(", ")} and ${blockers.at(-1)}`;
}

function GrantRoleForm(props: {
  api: PhaseTwoApi;
  csrfToken: string;
  delegation: readonly EffectiveTenantDelegationView[];
  onCancel: () => void;
  onGranted: () => void;
  pairKey: string;
  tenantId: string;
  userId: string;
}): React.JSX.Element {
  const model = useGrantRoleFormModel(props);
  return <GrantRoleFormView model={model.data} />;
}

function useGrantRoleFormModel({
  api,
  csrfToken,
  delegation,
  onCancel,
  onGranted,
  pairKey,
  tenantId,
  userId,
}: {
  api: PhaseTwoApi;
  csrfToken: string;
  delegation: readonly EffectiveTenantDelegationView[];
  onCancel: () => void;
  onGranted: () => void;
  pairKey: string;
  tenantId: string;
  userId: string;
}) {
  const { clearSession, session } = useSession();
  const id = useId();
  type RoleState =
    | {
        items: readonly DelegableRoleChoice[];
        kind: "ready";
        nextCursor?: string;
      }
    | { kind: "error"; message: string }
    | { kind: "loading" };
  const roleRequestKey = JSON.stringify([
    pairKey,
    delegationFingerprint(delegation),
  ]);
  const [roleSnapshot, setRoleSnapshot] = useState<PairSnapshot<RoleState>>(
    () => ({ pairKey: roleRequestKey, state: { kind: "loading" } }),
  );
  const roleState =
    roleSnapshot.pairKey === roleRequestKey
      ? roleSnapshot.state
      : { kind: "loading" as const };
  const [formError, setFormError] = useState<string | null>(null);
  const [isSaving, setIsSaving] = useState(false);
  const idempotencyBindingRef = useRef<{
    fingerprint: string;
    key: string;
  } | null>(null);
  const roleRequestRef = useRef(roleRequestKey);
  useLayoutEffect(() => {
    roleRequestRef.current = roleRequestKey;
  });
  const roleLoadGenerationRef = useRef(0);
  const rolePaginationGenerationRef = useRef(0);
  const rolePaginationRequestRef = useRef<PaginationRequest | null>(null);
  const roleCursorHistoryRef = useRef(new Set<string>());
  const [rolePaginationSnapshot, setRolePaginationSnapshot] = useState<
    PairSnapshot<PaginationState>
  >(() => ({ pairKey: roleRequestKey, state: { loading: false } }));
  const rolePaginationState =
    rolePaginationSnapshot.pairKey === roleRequestKey
      ? rolePaginationSnapshot.state
      : { loading: false };
  const { control, handleSubmit, register } = useForm<GrantFormValues>({
    defaultValues: { expiresAt: "", reason: "", roleId: "" },
  });
  const selectedRoleId = useWatch({ control, name: "roleId" });
  const selectedRole =
    roleState.kind === "ready"
      ? roleState.items.find((choice) => choice.role.id === selectedRoleId)
      : undefined;

  useEffect(() => {
    const generation = roleLoadGenerationRef.current + 1;
    roleLoadGenerationRef.current = generation;
    rolePaginationGenerationRef.current += 1;
    rolePaginationRequestRef.current?.controller.abort();
    rolePaginationRequestRef.current = null;
    roleCursorHistoryRef.current = new Set();
    setRolePaginationSnapshot({
      pairKey: roleRequestKey,
      state: { loading: false },
    });
    const controller = new AbortController();
    setRoleSnapshot({
      pairKey: roleRequestKey,
      state: { kind: "loading" },
    });
    void loadDelegableRolePage(
      api,
      tenantId,
      delegation,
      undefined,
      controller.signal,
    )
      .then((page) => {
        if (
          !controller.signal.aborted &&
          roleRequestRef.current === roleRequestKey &&
          roleLoadGenerationRef.current === generation
        ) {
          if (page.nextCursor) {
            roleCursorHistoryRef.current.add(page.nextCursor);
          }
          setRoleSnapshot({
            pairKey: roleRequestKey,
            state: {
              items: mergeDelegableRoleChoices([], page.items),
              kind: "ready",
              ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
            },
          });
        }
      })
      .catch((caught: unknown) => {
        if (
          !controller.signal.aborted &&
          roleRequestRef.current === roleRequestKey &&
          roleLoadGenerationRef.current === generation
        ) {
          if (caught instanceof PhaseTwoApiError && caught.status === 401) {
            clearSession(session.id);
            return;
          }
          setRoleSnapshot({
            pairKey: roleRequestKey,
            state: {
              kind: "error",
              message: describePhaseTwoError(
                caught,
                "Delegable roles could not be loaded.",
              ),
            },
          });
        }
      });
    return () => {
      controller.abort();
      rolePaginationGenerationRef.current += 1;
      rolePaginationRequestRef.current?.controller.abort();
      rolePaginationRequestRef.current = null;
    };
  }, [api, clearSession, delegation, roleRequestKey, session.id, tenantId]);

  async function loadMoreRoleOptions(): Promise<void> {
    if (
      roleState.kind !== "ready" ||
      !roleState.nextCursor ||
      rolePaginationState.loading
    ) {
      return;
    }
    const cursor = roleState.nextCursor;
    const expectedRequestKey = roleRequestKey;
    rolePaginationRequestRef.current?.controller.abort();
    const controller = new AbortController();
    const generation = rolePaginationGenerationRef.current + 1;
    rolePaginationGenerationRef.current = generation;
    rolePaginationRequestRef.current = {
      controller,
      cursor,
      generation,
      pairKey: expectedRequestKey,
    };
    setRolePaginationSnapshot({
      pairKey: expectedRequestKey,
      state: { loading: true },
    });
    try {
      const page = await loadDelegableRolePage(
        api,
        tenantId,
        delegation,
        cursor,
        controller.signal,
      );
      if (
        roleRequestRef.current !== expectedRequestKey ||
        !isCurrentPaginationRequest(
          rolePaginationRequestRef.current,
          expectedRequestKey,
          cursor,
          generation,
        )
      ) {
        return;
      }
      if (
        page.nextCursor &&
        (page.nextCursor === cursor ||
          roleCursorHistoryRef.current.has(page.nextCursor))
      ) {
        throw new Error("The role cursor did not advance.");
      }
      if (page.nextCursor) {
        roleCursorHistoryRef.current.add(page.nextCursor);
      }
      setRoleSnapshot((current) => {
        if (
          current.pairKey !== expectedRequestKey ||
          current.state.kind !== "ready" ||
          current.state.nextCursor !== cursor
        ) {
          return current;
        }
        return {
          pairKey: expectedRequestKey,
          state: {
            items: mergeDelegableRoleChoices(current.state.items, page.items),
            kind: "ready",
            ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
          },
        };
      });
    } catch (caught) {
      if (
        roleRequestRef.current !== expectedRequestKey ||
        !isCurrentPaginationRequest(
          rolePaginationRequestRef.current,
          expectedRequestKey,
          cursor,
          generation,
        )
      ) {
        return;
      }
      if (caught instanceof PhaseTwoApiError && caught.status === 401) {
        clearSession(session.id);
        return;
      }
      setRolePaginationSnapshot({
        pairKey: expectedRequestKey,
        state: {
          error: describePhaseTwoError(
            caught,
            "More delegable role options could not be loaded.",
          ),
          loading: true,
        },
      });
    } finally {
      if (
        roleRequestRef.current === expectedRequestKey &&
        isCurrentPaginationRequest(
          rolePaginationRequestRef.current,
          expectedRequestKey,
          cursor,
          generation,
        )
      ) {
        rolePaginationRequestRef.current = null;
        setRolePaginationSnapshot((current) =>
          current.pairKey === expectedRequestKey
            ? {
                pairKey: expectedRequestKey,
                state: { ...current.state, loading: false },
              }
            : current,
        );
      }
    }
  }

  const submit = handleSubmit(async (rawValues) => {
    const parsed = grantFormSchema.safeParse(rawValues);
    if (!parsed.success) {
      setFormError(
        parsed.error.issues[0]?.message ?? "Review the grant fields.",
      );
      return;
    }
    const parsedExpiry = parsed.data.expiresAt
      ? Date.parse(parsed.data.expiresAt)
      : undefined;
    if (parsedExpiry !== undefined && Number.isNaN(parsedExpiry)) {
      setFormError("Choose a valid grant expiry.");
      return;
    }
    const expiry =
      parsedExpiry === undefined
        ? undefined
        : new Date(parsedExpiry).toISOString();
    const input = {
      ...(expiry ? { expiresAt: expiry } : {}),
      reason: parsed.data.reason,
      roleId: parsed.data.roleId,
    };
    const bindingPayload = { input, tenantId, userId };
    const boundReplay = isPayloadBoundToIdempotencyKey(
      idempotencyBindingRef,
      bindingPayload,
    );
    const choice =
      roleState.kind === "ready"
        ? roleState.items.find((item) => item.role.id === parsed.data.roleId)
        : undefined;
    if (!choice && !boundReplay) {
      setFormError("Select a role within your live delegation ceiling.");
      return;
    }
    if (expiry && Date.parse(expiry) <= Date.now() && !boundReplay) {
      setFormError("Choose a future grant expiry.");
      return;
    }
    if (!boundReplay && choice?.delegableUntil) {
      if (!expiry) {
        setFormError(
          "This role requires an expiry before your effective delegation horizon.",
        );
        return;
      }
      const expiryInstant = parseRfc3339Instant(expiry);
      const delegableUntilInstant = parseRfc3339Instant(choice.delegableUntil);
      if (
        expiryInstant === undefined ||
        delegableUntilInstant === undefined ||
        expiryInstant > delegableUntilInstant
      ) {
        setFormError(
          "The grant must expire on or before your effective delegation horizon.",
        );
        return;
      }
    }

    setFormError(null);
    setIsSaving(true);
    try {
      await api.grantUserRole(
        csrfToken,
        tenantId,
        userId,
        idempotencyKeyForPayload(idempotencyBindingRef, bindingPayload),
        input,
      );
      onGranted();
    } catch (caught) {
      if (caught instanceof PhaseTwoApiError && caught.status === 401) {
        clearSession(session.id);
        return;
      }
      setFormError(
        describePhaseTwoError(
          caught,
          "The role was not granted. Your input is preserved.",
        ),
      );
    } finally {
      setIsSaving(false);
    }
  });

  return {
    kind: "ready" as const,
    data: {
      control,
      formError,
      id,
      isSaving,
      loadMoreRoleOptions,
      onCancel,
      register,
      rolePaginationState,
      roleState,
      selectedRole,
      submit,
    },
  };
}

function GrantRoleFormView({
  model,
}: {
  model: Extract<
    ReturnType<typeof useGrantRoleFormModel>,
    { kind: "ready" }
  >["data"];
}): React.JSX.Element {
  return <RoleGrantEditor model={model} />;
}

async function loadDelegableRolePage(
  api: PhaseTwoApi,
  tenantId: string,
  delegation: readonly EffectiveTenantDelegationView[],
  cursor: string | undefined,
  signal: AbortSignal,
): Promise<{
  items: readonly DelegableRoleChoice[];
  nextCursor?: string;
}> {
  const page = await api.listTenantRoles(tenantId, {
    ...(cursor ? { after: cursor } : {}),
    signal,
  });
  if (page.items.some((role) => role.tenantId !== tenantId)) {
    throw new Error("The role response escaped the active tenant.");
  }
  const roleIds = new Set<string>();
  for (const role of page.items) {
    if (!role.archived && role.principalKind === "human") {
      roleIds.add(role.id);
    }
  }
  const roles = await Promise.all(
    [...roleIds].map(async (roleId) => {
      const result = await api.getTenantRole(tenantId, roleId, signal);
      if (result.value.tenantId !== tenantId || result.value.id !== roleId) {
        throw new Error("The role response escaped the active tenant.");
      }
      return result.value;
    }),
  );
  return {
    items: roles.flatMap((role) => {
      if (role.archived) {
        return [];
      }
      const choice = deriveDelegableRoleChoice(role, delegation);
      return choice ? [choice] : [];
    }),
    ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
  };
}

function assertTenantUsers(
  users: readonly TenantUserSummaryView[],
  tenantId: string,
): void {
  if (users.some((user) => user.tenantId !== tenantId)) {
    throw new Error("The user response escaped the active tenant.");
  }
}

function assertDirectGrants(
  grants: readonly DirectUserRoleGrantView[],
  tenantId: string,
  userId: string,
): void {
  if (
    grants.some(
      (grant) => grant.tenantId !== tenantId || grant.userId !== userId,
    )
  ) {
    throw new Error(
      "The role grant response escaped the requested tenant user.",
    );
  }
  if (
    grants.some(
      (grant) =>
        !Number.isSafeInteger(grant.version) ||
        grant.version <= 0 ||
        grant.version > maximumDirectGrantVersion,
    )
  ) {
    throw new Error("The role grant response contained an invalid version.");
  }
  if (
    grants.some((grant) => {
      const match =
        typeof grant.etag === "string"
          ? directGrantEntityTagPrefixPattern.exec(grant.etag)
          : null;
      return !match || match[1] !== String(grant.version);
    })
  ) {
    throw new Error(
      "The role grant response contained an ETag/version mismatch.",
    );
  }
  if (
    grants.some(
      (grant) =>
        grant.provenance.expiresAt !== undefined &&
        parseRfc3339Instant(grant.provenance.expiresAt) === undefined,
    )
  ) {
    throw new Error("The role grant response contained an invalid expiry.");
  }
}

function deriveInitialUserListState(
  tenantId: string | undefined,
  status: string,
  message: string | undefined,
  canRead: boolean,
): UserListState {
  if (!tenantId) {
    return { kind: "inactive" };
  }
  if (status === "error") {
    return {
      kind: "error",
      message:
        message ??
        "Live tenant authority is unavailable. User access stays closed.",
    };
  }
  if (status === "forbidden" || (status === "ready" && !canRead)) {
    return { kind: "forbidden" };
  }
  return { kind: "loading" };
}

function mergeDirectGrantEntries(
  current: readonly DirectGrantEntry[],
  incoming: readonly DirectUserRoleGrantView[],
  originCursor: string | undefined,
): readonly DirectGrantEntry[] {
  const grants = new Map(
    current.map((entry) => [entry.grant.id, entry] as const),
  );
  for (const grant of incoming) {
    if (
      !Number.isSafeInteger(grant.version) ||
      grant.version <= 0 ||
      grant.version > maximumDirectGrantVersion
    ) {
      throw new Error("The role grant response contained an invalid version.");
    }
    const existing = grants.get(grant.id);
    if (!existing || grant.version > existing.grant.version) {
      grants.set(grant.id, {
        grant,
        ...(originCursor === undefined ? {} : { originCursor }),
      });
      continue;
    }
    // Inventory pages are unordered snapshots. A nested role-summary change can
    // legitimately change the representation ETag without incrementing the edge.
    // Retain the first accepted entry and its page origin until an exact refresh.
  }
  return [...grants.values()];
}

function directGrantRefreshAdvanced(
  rejected: DirectGrantEntry,
  candidate: DirectGrantEntry,
): boolean {
  return (
    candidate.grant.version > rejected.grant.version ||
    (candidate.grant.version === rejected.grant.version &&
      candidate.grant.etag !== rejected.grant.etag)
  );
}

function mergeRefreshedDirectGrantEntry(
  current: readonly DirectGrantEntry[],
  rejected: DirectGrantEntry,
  candidate: DirectGrantEntry,
): { entry: DirectGrantEntry; items: readonly DirectGrantEntry[] } {
  const index = current.findIndex(
    (entry) => entry.grant.id === candidate.grant.id,
  );
  if (index < 0 || rejected.grant.id !== candidate.grant.id) {
    throw new Error("The refreshed grant could not be merged.");
  }
  const existing = current[index];
  if (!existing) {
    throw new Error("The refreshed grant could not be merged.");
  }
  if (existing.grant.version > candidate.grant.version) {
    return { entry: existing, items: current };
  }
  if (
    existing.grant.version === candidate.grant.version &&
    existing.grant.etag === candidate.grant.etag
  ) {
    return { entry: existing, items: current };
  }
  if (
    existing.grant.version === rejected.grant.version &&
    existing.grant.etag === rejected.grant.etag
  ) {
    const items = [...current];
    items[index] = candidate;
    return { entry: candidate, items };
  }
  if (
    existing.grant.version === candidate.grant.version ||
    existing.grant.version === rejected.grant.version
  ) {
    throw new Error(
      "The exact grant refresh encountered an ambiguous same-version ETag.",
    );
  }
  if (candidate.grant.version > existing.grant.version) {
    const items = [...current];
    items[index] = candidate;
    return { entry: candidate, items };
  }
  return { entry: existing, items: current };
}

function findDirectGrantEntry(
  snapshot: PairSnapshot<GrantListState>,
  requestKey: string,
  grantId: string,
): DirectGrantEntry | undefined {
  return snapshot.pairKey === requestKey && snapshot.state.kind === "ready"
    ? snapshot.state.items.find((entry) => entry.grant.id === grantId)
    : undefined;
}

function mergeDelegableRoleChoices(
  current: readonly DelegableRoleChoice[],
  incoming: readonly DelegableRoleChoice[],
): readonly DelegableRoleChoice[] {
  const choices = new Map(
    current.map((choice) => [choice.role.id, choice] as const),
  );
  for (const choice of incoming) {
    choices.set(choice.role.id, choice);
  }
  return [...choices.values()];
}

function UserListSkeleton(): React.JSX.Element {
  return (
    <div className="tenant-list-skeleton" aria-label="Loading tenant users">
      <span />
      <span />
      <span />
    </div>
  );
}

function formatStatus(value: string): string {
  return value.replaceAll("_", " ");
}

function formatTimestamp(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.valueOf())
    ? "Unavailable"
    : dateTimeFormatter.format(date);
}

function toLocalDateTime(value: string): string {
  const date = new Date(value);
  const offset = date.getTimezoneOffset() * 60_000;
  return new Date(date.valueOf() - offset).toISOString().slice(0, 19);
}

function delegationFingerprint(
  delegation: readonly EffectiveTenantDelegationView[],
): string {
  return delegation
    .map(
      (entry) =>
        `${entry.permissionKey}:${entry.scope}:${entry.delegableUntil ?? "unbounded"}`,
    )
    .toSorted()
    .join("|");
}

function isCurrentPaginationRequest(
  request: PaginationRequest | null,
  pairKey: string,
  cursor: string,
  generation: number,
): boolean {
  return (
    request?.pairKey === pairKey &&
    request.cursor === cursor &&
    request.generation === generation &&
    !request.controller.signal.aborted
  );
}

function UserWorkspace({
  model,
}: {
  model: React.ComponentProps<typeof TenantUsersPageView>["model"];
}): React.ReactNode {
  const { listState, paginationError, setLoadAttempt } = model;
  return (
    <div className="content tenant-admin-page">
      <section className="page-heading" aria-labelledby="users-page-title">
        <div>
          <p className="section-label">Membership orbit / Phase 2B</p>
          <h1 id="users-page-title">Tenant users</h1>
          <p>
            Review tenant-scoped membership identities and the provenance,
            expiry, and lifecycle of their direct role grants. No global user
            catalog is exposed here.
          </p>
        </div>
        <Badge variant="outline">
          <Users aria-hidden="true" /> Tenant projection
        </Badge>
      </section>

      {paginationError ? (
        <FocusedError
          title="More users could not be loaded"
          message={paginationError}
        />
      ) : null}
      {listState.kind === "loading" ? <UserListSkeleton /> : null}
      {listState.kind === "error" ? (
        <div className="tenant-admin-error">
          <FocusedError message={listState.message} />
          <Button
            type="button"
            variant="outline"
            onClick={() => setLoadAttempt((attempt) => attempt + 1)}
          >
            <RefreshCw aria-hidden="true" /> Retry user inventory
          </Button>
        </div>
      ) : null}
      {listState.kind === "ready" && listState.items.length === 0 ? (
        <div className="tenant-empty">
          <Users aria-hidden="true" />
          <h2>No tenant users returned</h2>
          <p>The server returned no membership identities for this tenant.</p>
        </div>
      ) : null}
      {<MembershipInventory model={model} />}

      {<UserAccessAction model={model} />}

      {<MembershipLifecycleAction model={model} />}
    </div>
  );
}

function UserAccessDialogContent({
  model,
}: {
  model: React.ComponentProps<typeof UserAccessDialogView>["model"];
}): React.ReactNode {
  const {
    api,
    csrfToken,
    delegation,
    dialogKey,
    dialogMountedRef,
    granting,
    onAuthorityChanged,
    onOpenChange,
    setGrantingKey,
    setLoadRevision,
    tenantId,
    user,
  } = model;
  return (
    <Dialog open onOpenChange={onOpenChange}>
      <DialogContent className="user-access-dialog">
        <DialogHeader>
          <DialogTitle>
            {granting
              ? "Grant a tenant role"
              : `Access · ${user.user.displayName}`}
          </DialogTitle>
          <DialogDescription>
            {granting
              ? "The selected role must fit your live exact-tuple delegation ceiling."
              : "Direct grants and available inherited group paths keep their source-qualified provenance separate."}
          </DialogDescription>
        </DialogHeader>
        {granting ? (
          <GrantRoleForm
            api={api}
            csrfToken={csrfToken}
            delegation={delegation}
            onCancel={() => setGrantingKey(null)}
            onGranted={() => {
              if (!dialogMountedRef.current) {
                return;
              }
              onAuthorityChanged();
              setGrantingKey(null);
              setLoadRevision((revision) => revision + 1);
            }}
            pairKey={dialogKey}
            tenantId={tenantId}
            userId={user.user.id}
          />
        ) : (
          <UserGrantHistory model={model} />
        )}
      </DialogContent>
    </Dialog>
  );
}

function DirectGrantDetails({
  model,
}: {
  model: React.ComponentProps<typeof DirectGrantCardView>["model"];
}): React.ReactNode {
  const {
    authorityBlocker,
    draft,
    grant,
    refreshStaleGrant,
    rejectedRefreshEntry,
    roleTarget,
    staleRefreshState,
  } = model;
  return (
    <article className="grant-card">
      <header>
        <div>
          <strong>{grant.role.name}</strong>
          <small>{grant.role.key}</small>
        </div>
        <Badge variant={grant.state === "active" ? "secondary" : "outline"}>
          {formatStatus(grant.state)}
        </Badge>
      </header>
      <DirectGrantMetadata model={model} />
      {authorityBlocker ? (
        <p className="capability-note">
          This direct path no longer contributes authority because{" "}
          {authorityBlocker}. The {formatStatus(grant.state)} badge describes
          only the edge lifecycle.
        </p>
      ) : null}
      <blockquote>{grant.provenance.reason}</blockquote>
      {draft.error ? (
        <FocusedError title="Grant action failed" message={draft.error} />
      ) : null}
      {draft.notice ? (
        <p className="capability-note" role="status">
          {draft.notice}
        </p>
      ) : null}
      {grant.state !== "revoked" &&
      !isManagedByAuthorizationApi(grant.managedByAuthorizationApi) ? (
        <p className="source-owner-note">
          Not managed by the authorization API (source:{" "}
          {formatStatus(grant.provenance.sourceKind)}); direct controls cannot
          revoke this grant.
        </p>
      ) : null}
      {rejectedRefreshEntry ? (
        <Button
          type="button"
          variant="outline"
          disabled={staleRefreshState === "refreshing"}
          aria-label={`Retry current grant refresh for ${roleTarget}`}
          onClick={() => void refreshStaleGrant(rejectedRefreshEntry)}
        >
          <RefreshCw aria-hidden="true" />
          {staleRefreshState === "refreshing"
            ? "Refreshing grant…"
            : "Retry grant refresh"}
        </Button>
      ) : null}
      {<DirectGrantRevokeAction model={model} />}
    </article>
  );
}

function RoleGrantEditor({
  model,
}: {
  model: React.ComponentProps<typeof GrantRoleFormView>["model"];
}): React.ReactNode {
  const {
    formError,
    isSaving,
    loadMoreRoleOptions,
    onCancel,
    rolePaginationState,
    roleState,
    submit,
  } = model;
  return (
    <form className="grant-role-form" onSubmit={submit} noValidate>
      {formError ? (
        <FocusedError title="Role not granted" message={formError} />
      ) : null}
      {roleState.kind === "loading" ? <UserListSkeleton /> : null}
      {roleState.kind === "error" ? (
        <FocusedError
          title="Role catalog unavailable"
          message={roleState.message}
        />
      ) : null}
      {rolePaginationState.error ? (
        <FocusedError
          title="More role options could not be loaded"
          message={rolePaginationState.error}
        />
      ) : null}
      {roleState.kind === "ready" && roleState.items.length === 0 ? (
        <div className="grant-empty">
          <ShieldCheck aria-hidden="true" />
          <p>
            {roleState.nextCursor
              ? "No delegable role was found on the loaded pages yet."
              : "No active role fits your live delegation ceiling."}
          </p>
        </div>
      ) : null}
      {<RoleGrantFields model={model} />}
      {roleState.kind === "ready" && roleState.nextCursor ? (
        <Button
          type="button"
          variant="outline"
          disabled={isSaving || rolePaginationState.loading}
          onClick={() => void loadMoreRoleOptions()}
        >
          <ArrowDown aria-hidden="true" />
          {rolePaginationState.loading
            ? "Loading role options…"
            : "Load more role options"}
        </Button>
      ) : null}
      <DialogFooter>
        <Button
          type="button"
          variant="ghost"
          disabled={isSaving}
          onClick={onCancel}
        >
          Cancel
        </Button>
        <Button
          type="submit"
          disabled={
            isSaving ||
            roleState.kind !== "ready" ||
            roleState.items.length === 0
          }
        >
          {isSaving ? "Granting role…" : "Grant role"}
        </Button>
      </DialogFooter>
    </form>
  );
}

function MembershipInventory({
  model,
}: {
  model: React.ComponentProps<typeof UserWorkspace>["model"];
}): React.ReactNode {
  const {
    canManageMembership,
    isLoadingMore,
    listState,
    loadMore,
    openMembershipLifecycle,
    openUserAccess,
  } = model;
  return listState.kind === "ready" && listState.items.length > 0 ? (
    <section
      className="authority-inventory"
      aria-labelledby="user-inventory-title"
    >
      <div className="section-heading">
        <div>
          <p className="section-label">Server inventory</p>
          <h2 id="user-inventory-title">Membership identities</h2>
        </div>
      </div>
      <Table className="authority-table">
        <TableCaption className="sr-only">
          Users in the active tenant membership projection
        </TableCaption>
        <TableColumnHeaders
          columns={["User", "Membership", "Legacy label", "Updated", "Actions"]}
        />
        <TableBody>
          {listState.items.map((item) => (
            <TableRow key={item.membershipId}>
              <TableCell>
                <span className="role-name-cell">
                  <strong>{item.user.displayName}</strong>
                  <small>{item.user.email}</small>
                </span>
              </TableCell>
              <TableCell>
                <Badge
                  variant={
                    item.membershipStatus === "active" ? "secondary" : "outline"
                  }
                >
                  {item.membershipStatus === "suspended" ? (
                    <Ban aria-hidden="true" />
                  ) : item.membershipStatus === "active" ? (
                    <ShieldCheck aria-hidden="true" />
                  ) : (
                    <UserRound aria-hidden="true" />
                  )}
                  {formatStatus(item.membershipStatus)}
                </Badge>
              </TableCell>
              <TableCell>{formatStatus(item.legacyMembershipRole)}</TableCell>
              <TableCell>{formatTimestamp(item.updatedAt)}</TableCell>
              <TableCell>
                <span className="flex flex-wrap gap-1">
                  <Button
                    type="button"
                    size="sm"
                    variant="ghost"
                    aria-label={`Review access for ${item.user.displayName} (${item.user.email})`}
                    onClick={() => openUserAccess(item)}
                  >
                    <KeyRound aria-hidden="true" /> Access
                  </Button>
                  {canManageMembership &&
                  (item.membershipStatus === "active" ||
                    (item.membershipStatus === "suspended" &&
                      item.user.active)) ? (
                    <Button
                      type="button"
                      size="sm"
                      variant={
                        item.membershipStatus === "active"
                          ? "destructive"
                          : "outline"
                      }
                      aria-label={`${
                        item.membershipStatus === "active"
                          ? "Suspend"
                          : "Reactivate"
                      } membership for ${item.user.displayName} (${item.user.email})`}
                      onClick={() => openMembershipLifecycle(item)}
                    >
                      {item.membershipStatus === "active" ? (
                        <Ban aria-hidden="true" />
                      ) : (
                        <RotateCcw aria-hidden="true" />
                      )}
                      {item.membershipStatus === "active"
                        ? "Suspend"
                        : "Reactivate"}
                    </Button>
                  ) : null}
                </span>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      {listState.nextCursor ? (
        <Button
          type="button"
          variant="outline"
          disabled={isLoadingMore}
          onClick={() => void loadMore()}
        >
          <ArrowDown aria-hidden="true" />
          {isLoadingMore ? "Loading users…" : "Load more users"}
        </Button>
      ) : null}
    </section>
  ) : null;
}

function UserAccessAction({
  model,
}: {
  model: React.ComponentProps<typeof UserWorkspace>["model"];
}): React.ReactNode {
  const {
    api,
    authority,
    authorityReadyRef,
    canGrant,
    closeUserAccess,
    requestPair,
    requestPairRef,
    selectedUser,
    selectedUserSelection,
    session,
    tenantId,
  } = model;
  return tenantId && selectedUser && selectedUserSelection ? (
    <UserAccessDialog
      api={api}
      canGrant={canGrant}
      csrfToken={session.csrfToken}
      delegation={authority.authority?.delegationCeiling ?? []}
      effectiveGrants={
        selectedUser.user.id === session.user.id
          ? (authority.authority?.roleGrants ?? [])
          : []
      }
      onAuthorityChanged={() => {
        if (
          requestPairRef.current === requestPair &&
          authorityReadyRef.current
        ) {
          authority.reload();
        }
      }}
      onOpenChange={(open) => {
        if (!open) {
          closeUserAccess();
        }
      }}
      pairKey={requestPair}
      key={`${requestPair}:${selectedUser.user.id}:${selectedUserSelection.generation}`}
      tenantId={tenantId}
      user={selectedUser}
    />
  ) : null;
}

function MembershipLifecycleAction({
  model,
}: {
  model: React.ComponentProps<typeof UserWorkspace>["model"];
}): React.ReactNode {
  const {
    api,
    applyMembershipLifecycle,
    authorityReadyRef,
    clearSession,
    requestPairRef,
    selectedLifecycle,
    session,
    setLifecycleSelection,
    setLoadAttempt,
    tenantId,
  } = model;
  return tenantId && selectedLifecycle ? (
    <MembershipLifecycleDialog
      api={api}
      csrfToken={session.csrfToken}
      isCurrent={() =>
        requestPairRef.current === selectedLifecycle.pairKey &&
        authorityReadyRef.current
      }
      key={`${selectedLifecycle.pairKey}:${selectedLifecycle.user.membershipId}`}
      onCompleted={(receipt) => {
        if (
          receipt.status === "suspended" &&
          receipt.userId === session.user.id
        ) {
          clearSession(session.id);
          return;
        }
        applyMembershipLifecycle(selectedLifecycle.user, {
          etag: receipt.etag,
          lifecycleRevision: receipt.lifecycleRevision,
          membershipStatus: receipt.status,
          updatedAt: receipt.updatedAt,
        });
      }}
      onOpenChange={(open) => {
        if (!open) {
          setLifecycleSelection(null);
        }
      }}
      onStale={() => setLoadAttempt((attempt) => attempt + 1)}
      tenantId={tenantId}
      user={selectedLifecycle.user}
    />
  ) : null;
}

function UserGrantHistory({
  model,
}: {
  model: React.ComponentProps<typeof UserAccessDialogContent>["model"];
}): React.ReactNode {
  const {
    api,
    canGrant,
    clearRevokeDraft,
    csrfToken,
    dialogKey,
    dialogMountedRef,
    effectiveGrants,
    grantPaginationState,
    grantRequestKey,
    grantState,
    isCurrentDialogRequest,
    onAuthorityChanged,
    refreshDirectGrant,
    revokeDrafts,
    setGrantingKey,
    setLoadRevision,
    tenantId,
    updateRevokeDraft,
    user,
  } = model;
  return (
    <>
      <div className="user-access-identity">
        <UserRound aria-hidden="true" />
        <span>
          <strong>{user.user.displayName}</strong>
          <small>{user.user.email}</small>
        </span>
        <Badge variant="outline">{formatStatus(user.membershipStatus)}</Badge>
        <Badge variant={user.user.active ? "secondary" : "outline"}>
          {user.user.active ? "User active" : "User disabled"}
        </Badge>
      </div>
      {grantState.kind === "loading" ? <UserListSkeleton /> : null}
      {grantState.kind === "forbidden" ? (
        <FocusedError
          title="Grant history denied"
          message="The server denied access to this user's direct role grants."
        />
      ) : null}
      {grantState.kind === "error" ? (
        <FocusedError message={grantState.message} />
      ) : null}
      {grantState.kind === "ready" && grantState.items.length === 0 ? (
        <div className="grant-empty">
          <ShieldCheck aria-hidden="true" />
          <p>No direct role grants were returned for this user.</p>
        </div>
      ) : null}
      {grantState.kind === "ready" && grantState.items.length > 0 ? (
        <DirectGrantInventory
          api={api}
          canGrant={canGrant}
          clearRevokeDraft={clearRevokeDraft}
          csrfToken={csrfToken}
          dialogMountedRef={dialogMountedRef}
          grantRequestKey={grantRequestKey}
          grantState={grantState}
          isCurrentDialogRequest={isCurrentDialogRequest}
          onAuthorityChanged={onAuthorityChanged}
          refreshDirectGrant={refreshDirectGrant}
          revokeDrafts={revokeDrafts}
          setLoadRevision={setLoadRevision}
          tenantId={tenantId}
          updateRevokeDraft={updateRevokeDraft}
          user={user}
        />
      ) : null}
      {grantPaginationState.error ? (
        <FocusedError
          title="More grant history could not be loaded"
          message={grantPaginationState.error}
        />
      ) : null}
      <GrantHistoryPagination model={model} />
      {effectiveGrants.some(
        (grant) =>
          grant.path.pathType === "group" && grant.path.group !== undefined,
      ) ? (
        <InheritedGroupPaths grants={effectiveGrants} />
      ) : null}
      <DialogFooter>
        {canGrant && grantState.kind !== "forbidden" ? (
          <Button type="button" onClick={() => setGrantingKey(dialogKey)}>
            <Plus aria-hidden="true" /> Grant role
          </Button>
        ) : null}
      </DialogFooter>
    </>
  );
}

function DirectGrantMetadata({
  model,
}: {
  model: React.ComponentProps<typeof DirectGrantDetails>["model"];
}): React.ReactNode {
  const { authorityBlocker, grant, userActive, userMembershipStatus } = model;
  return (
    <dl>
      <div>
        <dt>Edge lifecycle</dt>
        <dd>{formatStatus(grant.state)}</dd>
      </div>
      <div>
        <dt>Effective authority</dt>
        <dd>{authorityBlocker ? "Not contributing" : "Contributing"}</dd>
      </div>
      <div>
        <dt>Membership state</dt>
        <dd>{formatStatus(userMembershipStatus)}</dd>
      </div>
      <div>
        <dt>User state</dt>
        <dd>{userActive ? "Active" : "Disabled"}</dd>
      </div>
      <div>
        <dt>Authority path</dt>
        <dd>Direct</dd>
      </div>
      <div>
        <dt>Source kind</dt>
        <dd>{formatStatus(grant.provenance.sourceKind)}</dd>
      </div>
      <div>
        <dt>Source type</dt>
        <dd>{formatStatus(grant.provenance.sourceType)}</dd>
      </div>
      <div>
        <dt>Source ID</dt>
        <dd>{grant.provenance.sourceId}</dd>
      </div>
      <div>
        <dt>Source mode</dt>
        <dd>{grant.provenance.authoritative ? "Authoritative" : "Additive"}</dd>
      </div>
      <div>
        <dt>Granted</dt>
        <dd>{formatTimestamp(grant.provenance.grantedAt)}</dd>
      </div>
      <div>
        <dt>Expires</dt>
        <dd>
          {grant.provenance.expiresAt
            ? formatTimestamp(grant.provenance.expiresAt)
            : "No scheduled expiry"}
        </dd>
      </div>
      <div>
        <dt>Source retirement</dt>
        <dd>
          {grant.provenance.retiredAt
            ? formatTimestamp(grant.provenance.retiredAt)
            : "Source active"}
        </dd>
      </div>
      <div>
        <dt>Role state</dt>
        <dd>{grant.role.archived ? "Archived" : "Available"}</dd>
      </div>
      {grant.provenance.grantedByUserId ? (
        <div>
          <dt>Granted by</dt>
          <dd>{grant.provenance.grantedByUserId}</dd>
        </div>
      ) : null}
      {grant.state === "revoked" && grant.revokeReason ? (
        <div>
          <dt>Revocation reason</dt>
          <dd>{grant.revokeReason}</dd>
        </div>
      ) : null}
    </dl>
  );
}

function DirectGrantRevokeAction({
  model,
}: {
  model: React.ComponentProps<typeof DirectGrantDetails>["model"];
}): React.ReactNode {
  const {
    canGrant,
    draft,
    grant,
    id,
    isSaving,
    onCancel,
    onDraftChange,
    revoke,
    roleTarget,
    staleRefreshState,
  } = model;
  return canGrant && directGrantIsRevocable(grant) ? (
    draft.open ? (
      <div
        className="revoke-grant-form"
        role="group"
        aria-labelledby={`${id}-revoke-title`}
      >
        <strong id={`${id}-revoke-title`}>
          Revoke direct grant for {roleTarget}
        </strong>
        <FormField htmlFor={`${id}-revoke-reason`} label="Reason">
          <Textarea
            id={`${id}-revoke-reason`}
            aria-label={`Reason for revoking direct grant for ${roleTarget}`}
            value={draft.reason}
            maxLength={500}
            disabled={isSaving || staleRefreshState === "refreshing"}
            onChange={(event) => {
              const reason = event.currentTarget.value;
              onDraftChange((current) => ({
                ...current,
                error: null,
                notice: null,
                reason,
              }));
            }}
          />
        </FormField>
        <div>
          <Button
            type="button"
            variant="destructive"
            disabled={isSaving || staleRefreshState !== "idle"}
            aria-label={`${isSaving ? "Revoking" : "Confirm revoke"} direct grant for ${roleTarget}`}
            onClick={() => void revoke()}
          >
            <Trash2 aria-hidden="true" />
            {isSaving ? "Revoking…" : "Confirm revoke"}
          </Button>
          <Button
            type="button"
            variant="ghost"
            disabled={isSaving || staleRefreshState === "refreshing"}
            aria-label={`Keep grant for ${roleTarget}`}
            onClick={onCancel}
          >
            Keep grant
          </Button>
        </div>
      </div>
    ) : (
      <Button
        type="button"
        size="sm"
        variant="outline"
        aria-label={`Revoke direct grant for ${roleTarget}`}
        onClick={() =>
          onDraftChange((current) => ({
            ...current,
            error: null,
            notice: null,
            open: true,
          }))
        }
      >
        <Trash2 aria-hidden="true" /> Revoke
      </Button>
    )
  ) : null;
}

function RoleGrantFields({
  model,
}: {
  model: React.ComponentProps<typeof RoleGrantEditor>["model"];
}): React.ReactNode {
  const { control, id, isSaving, register, roleState, selectedRole } = model;
  return roleState.kind === "ready" && roleState.items.length > 0 ? (
    <>
      <FormField htmlFor={`${id}-grant-role`} label="Role">
        <Controller
          control={control}
          name="roleId"
          render={({ field }) => (
            <Select
              value={field.value}
              onValueChange={field.onChange}
              disabled={isSaving}
            >
              <SelectTrigger
                id={`${id}-grant-role`}
                className="grant-role-select"
              >
                <SelectValue placeholder="Select a role" />
              </SelectTrigger>
              <SelectContent>
                {roleState.items.map((choice) => (
                  <SelectItem key={choice.role.id} value={choice.role.id}>
                    {choice.role.name} ({choice.role.key})
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          )}
        />
      </FormField>
      <FormField
        htmlFor={`${id}-grant-expiry`}
        label="Grant expiry"
        optional={!selectedRole?.delegableUntil}
        hint={
          selectedRole?.delegableUntil
            ? `Must be on or before ${formatTimestamp(selectedRole.delegableUntil)}.`
            : "Leave empty only when the selected role has no effective delegation horizon."
        }
      >
        <Input
          id={`${id}-grant-expiry`}
          aria-describedby={`${id}-grant-expiry-hint`}
          type="datetime-local"
          min={toLocalDateTime(new Date().toISOString())}
          max={
            selectedRole?.delegableUntil
              ? toLocalDateTime(selectedRole.delegableUntil)
              : undefined
          }
          step={1}
          disabled={isSaving}
          {...register("expiresAt")}
        />
      </FormField>
      <FormField htmlFor={`${id}-grant-reason`} label="Reason">
        <Textarea
          id={`${id}-grant-reason`}
          maxLength={500}
          disabled={isSaving}
          {...register("reason")}
        />
      </FormField>
    </>
  ) : null;
}

interface DirectGrantInventoryProps {
  api: PhaseTwoApi;
  canGrant: boolean;
  clearRevokeDraft: (grantId: string) => void;
  csrfToken: string;
  dialogMountedRef: React.RefObject<boolean>;
  grantRequestKey: string;
  grantState: Extract<GrantListState, { kind: "ready" }>;
  isCurrentDialogRequest: (expectedRequestKey: string) => boolean;
  onAuthorityChanged: () => void;
  refreshDirectGrant: (
    rejectedEntry: DirectGrantEntry,
  ) => Promise<DirectUserRoleGrantView | null>;
  revokeDrafts: Readonly<Record<string, RevokeDraft>>;
  setLoadRevision: React.Dispatch<React.SetStateAction<number>>;
  tenantId: string;
  updateRevokeDraft: (
    grantId: string,
    update: (draft: RevokeDraft) => RevokeDraft,
  ) => void;
  user: TenantUserSummaryView;
}

function DirectGrantInventory({
  api,
  canGrant,
  clearRevokeDraft,
  csrfToken,
  dialogMountedRef,
  grantRequestKey,
  grantState,
  isCurrentDialogRequest,
  onAuthorityChanged,
  refreshDirectGrant,
  revokeDrafts,
  setLoadRevision,
  tenantId,
  updateRevokeDraft,
  user,
}: DirectGrantInventoryProps): React.JSX.Element {
  return (
    <div className="grant-list">
      {grantState.items.map((entry) => (
        <DirectGrantCard
          api={api}
          canGrant={canGrant}
          csrfToken={csrfToken}
          draft={revokeDrafts[entry.grant.id] ?? emptyRevokeDraft}
          entry={entry}
          isDialogActive={() => dialogMountedRef.current}
          isGrantViewCurrent={() => isCurrentDialogRequest(grantRequestKey)}
          key={entry.grant.id}
          onCancel={() => clearRevokeDraft(entry.grant.id)}
          onDraftChange={(update) => updateRevokeDraft(entry.grant.id, update)}
          onRevoked={() => {
            if (!dialogMountedRef.current) {
              return;
            }
            clearRevokeDraft(entry.grant.id);
            onAuthorityChanged();
            setLoadRevision((revision) => revision + 1);
          }}
          onRefreshStale={refreshDirectGrant}
          tenantId={tenantId}
          userActive={user.user.active}
          userMembershipStatus={user.membershipStatus}
        />
      ))}
    </div>
  );
}

function GrantHistoryPagination({
  model,
}: {
  model: React.ComponentProps<typeof UserGrantHistory>["model"];
}): React.ReactNode {
  const { grantPaginationState, grantState, loadMoreGrantHistory } = model;
  return grantState.kind === "ready" && grantState.nextCursor ? (
    <Button
      type="button"
      variant="outline"
      disabled={grantPaginationState.loading}
      onClick={() => void loadMoreGrantHistory()}
    >
      <ArrowDown aria-hidden="true" />
      {grantPaginationState.loading
        ? "Loading grant history…"
        : "Load more grant history"}
    </Button>
  ) : null;
}
