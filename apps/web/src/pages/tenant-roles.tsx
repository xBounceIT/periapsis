import { Badge } from "@periapsis/ui/components/ui/badge";
import { Button } from "@periapsis/ui/components/ui/button";
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
import {
  Table,
  TableBody,
  TableCaption,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@periapsis/ui/components/ui/table";
import { Textarea } from "@periapsis/ui/components/ui/textarea";
import {
  createColumnHelper,
  tableFeatures,
  useTable,
} from "@tanstack/react-table";
import { Archive, ArrowDown, Eye, Plus, RefreshCw, Shield } from "lucide-react";
import {
  useCallback,
  useEffect,
  useId,
  useLayoutEffect,
  useMemo,
  useReducer,
  useRef,
} from "react";
import {
  Controller,
  useForm,
  type Control,
  type UseFormSetValue,
} from "react-hook-form";
import { TenantRequiredPage } from "../components/tenant-required-page";
import {
  mergeTenantRoles,
  sameRoleSummaryRepresentation,
  tryMergeTenantRoles,
  validRoleVersion,
} from "./tenant-roles-model";
import {
  reduceWorkspaceState,
  selectPairState,
  selectPairValue,
} from "./workspace-state";

import { z } from "zod";

import { useSession } from "../auth/session-context";
import { useTenantAuthority } from "../auth/tenant-authority-context";
import { FocusedError } from "../components/focused-error";
import { FormField } from "../components/form-field";
import { ServerDenied } from "../components/server-denied";
import { idempotencyKeyForPayload } from "../lib/payload-idempotency";
import {
  describePhaseTwoError,
  PhaseTwoApiError,
  tenantAuthorizationScopes,
  tenantPermissionKeys,
  type EffectiveTenantDelegationView,
  type PhaseTwoApi,
  type TenantPermissionView,
  type TenantRolePolicyView,
  type TenantRoleSummaryView,
  type TenantRoleView,
  type VersionedView,
} from "../lib/phase-two-types";
import { hasControlCharacters } from "../lib/text-validation";

const dateTimeFormatter = new Intl.DateTimeFormat(undefined, {
  day: "2-digit",
  month: "short",
  year: "numeric",
});

type RoleListState =
  | { kind: "error"; message: string }
  | { kind: "forbidden" }
  | { kind: "inactive" }
  | {
      items: readonly TenantRoleSummaryView[];
      kind: "ready";
      nextCursor?: string;
    }
  | { kind: "loading" };

type PermissionState =
  | { items: readonly TenantPermissionView[]; kind: "ready" }
  | { kind: "error"; message: string }
  | { kind: "loading" };

type DetailState =
  | { kind: "error"; message: string }
  | { kind: "loading" }
  | { kind: "ready"; role: VersionedView<TenantRoleView> };

interface PairSnapshot<T> {
  pairKey: string;
  state: T;
}

interface RoleSelection {
  generation: number;
  pairKey: string;
  roleId: string;
}

interface CreateRoleSelection {
  generation: number;
  pairKey: string;
}

interface RoleDetailRequest {
  controller: AbortController;
  generation: number;
  pairKey: string;
  roleId: string;
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

const roleTableFeatures = tableFeatures({});
const roleColumnHelper = createColumnHelper<
  typeof roleTableFeatures,
  TenantRoleSummaryView
>();

const roleTupleSchema = z.object({
  delegable: z.boolean(),
  granted: z.boolean(),
  permissionKey: z.enum(tenantPermissionKeys),
  scope: z.enum(tenantAuthorizationScopes),
});

const roleFormSchema = z
  .object({
    description: z
      .string()
      .max(500, "Use 500 characters or fewer.")
      .refine(
        (value) => !hasControlCharacters(value),
        "Use a description without control characters.",
      ),
    key: z
      .string()
      .trim()
      .regex(
        /^[a-z][a-z0-9_]{2,63}$/,
        "Use 3–64 lowercase letters, numbers, or underscores, starting with a letter.",
      ),
    name: z
      .string()
      .trim()
      .min(1, "Enter a role name.")
      .max(120)
      .refine(
        (value) => !hasControlCharacters(value),
        "Use a role name without control characters.",
      ),
    tuples: z.array(roleTupleSchema),
  })
  .superRefine((value, context) => {
    const seen = new Set<string>();
    for (const [index, tuple] of value.tuples.entries()) {
      const key = tupleKey(tuple.permissionKey, tuple.scope);
      if (seen.has(key)) {
        context.addIssue({
          code: "custom",
          message: "The permission and scope matrix contains a duplicate.",
          path: ["tuples", index],
        });
      }
      seen.add(key);
      if (tuple.delegable && !tuple.granted) {
        context.addIssue({
          code: "custom",
          message: "Delegation must remain subordinate to a granted tuple.",
          path: ["tuples", index, "delegable"],
        });
      }
    }
  });

type RoleFormValues = z.infer<typeof roleFormSchema>;
const roleEntityTagPattern = /^"v([1-9][0-9]*)"$/;

export function TenantRolesPage(): React.JSX.Element {
  const model = useTenantRolesPageModel();
  if (model.kind === "content") return model.content;
  return <TenantRolesPageView model={model.data} />;
}

function useTenantRolesPageModel() {
  const { api, clearSession, session } = useSession();
  const authority = useTenantAuthority();
  const tenantId = session.activeTenantId;
  const requestPair = JSON.stringify([session.id, tenantId ?? null]);
  const requestPairRef = useRef(requestPair);
  useLayoutEffect(() => {
    requestPairRef.current = requestPair;
  });
  const canRead = authority.hasPermission("role.read");
  const canManage = authority.hasPermission("role.manage");
  const authorityReady =
    Boolean(tenantId) && authority.status === "ready" && canRead;
  const authorityReadyRef = useRef(authorityReady);
  useLayoutEffect(() => {
    authorityReadyRef.current = authorityReady;
  });
  const initialListState = useMemo(
    () =>
      deriveInitialRoleListState(
        tenantId,
        authority.status,
        authority.message,
        canRead,
      ),
    [tenantId, authority.status, authority.message, canRead],
  );
  const [workspaceState, updateWorkspaceState] = useReducer(
    reduceWorkspaceState<TenantRolesPageState>,
    undefined,
    (): TenantRolesPageState => ({
      listSnapshot: (() => ({
        pairKey: requestPair,
        state: initialListState,
      }))(),
      permissionSnapshot: (() => ({
        pairKey: requestPair,
        state: { kind: "loading" },
      }))(),
      createSelection: null,
      loadAttempt: 0,
      paginationSnapshot: (() => ({
        pairKey: requestPair,
        state: { loading: false },
      }))(),
      roleSelection: null,
      detailSnapshot: (() => ({
        pairKey: requestPair,
        roleId: "",
        state: { kind: "loading" },
      }))(),
    }),
  );
  const {
    listSnapshot,
    permissionSnapshot,
    createSelection,
    loadAttempt,
    paginationSnapshot,
    roleSelection,
    detailSnapshot,
  } = workspaceState;
  const {
    setListSnapshot,
    setPermissionSnapshot,
    setCreateSelection,
    setLoadAttempt,
    setPaginationSnapshot,
    setRoleSelection,
    setDetailSnapshot,
  } = useMemo(
    () => ({
      setListSnapshot: (
        value: React.SetStateAction<TenantRolesPageState["listSnapshot"]>,
      ) => updateWorkspaceState({ listSnapshot: value }),
      setPermissionSnapshot: (
        value: React.SetStateAction<TenantRolesPageState["permissionSnapshot"]>,
      ) => updateWorkspaceState({ permissionSnapshot: value }),
      setCreateSelection: (
        value: React.SetStateAction<TenantRolesPageState["createSelection"]>,
      ) => updateWorkspaceState({ createSelection: value }),
      setLoadAttempt: (
        value: React.SetStateAction<TenantRolesPageState["loadAttempt"]>,
      ) => updateWorkspaceState({ loadAttempt: value }),
      setPaginationSnapshot: (
        value: React.SetStateAction<TenantRolesPageState["paginationSnapshot"]>,
      ) => updateWorkspaceState({ paginationSnapshot: value }),
      setRoleSelection: (
        value: React.SetStateAction<TenantRolesPageState["roleSelection"]>,
      ) => updateWorkspaceState({ roleSelection: value }),
      setDetailSnapshot: (
        value: React.SetStateAction<TenantRolesPageState["detailSnapshot"]>,
      ) => updateWorkspaceState({ detailSnapshot: value }),
    }),
    [updateWorkspaceState],
  );
  const listState = selectPairState(
    listSnapshot,
    requestPair,
    initialListState,
    authorityReady,
  );

  const permissionState = selectPairState(
    permissionSnapshot,
    requestPair,
    { kind: "loading" },
    authorityReady,
  );

  const createGenerationRef = useRef(0);

  const paginationState = selectPairState(paginationSnapshot, requestPair, {
    loading: false,
  });
  const isLoadingMore = paginationState.loading;
  const paginationError = paginationState.error ?? null;
  const paginationGenerationRef = useRef(0);
  const paginationRequestRef = useRef<PaginationRequest | null>(null);

  const detailGenerationRef = useRef(0);
  const detailRequestRef = useRef<RoleDetailRequest | null>(null);
  const activeCreateSelection = selectPairValue(
    createSelection,
    requestPair,
    authorityReady,
  );
  const createOpen = activeCreateSelection !== null;
  const selectedRole = selectPairValue(
    roleSelection,
    requestPair,
    authorityReady,
  );
  const selectedRoleId = selectedRole?.roleId ?? null;
  const detailState =
    selectedRoleId &&
    detailSnapshot.pairKey === requestPair &&
    detailSnapshot.roleId === selectedRoleId
      ? detailSnapshot.state
      : { kind: "loading" as const };

  useEffect(() => {
    if (authorityReady) {
      return;
    }
    createGenerationRef.current += 1;
    setCreateSelection(null);
    detailGenerationRef.current += 1;
    detailRequestRef.current?.controller.abort();
    detailRequestRef.current = null;
    updateWorkspaceState({
      roleSelection: null,
      detailSnapshot: {
        pairKey: requestPair,
        roleId: "",
        state: { kind: "loading" },
      },
    });
    paginationGenerationRef.current += 1;
    paginationRequestRef.current?.controller.abort();
    paginationRequestRef.current = null;
    updateWorkspaceState({
      paginationSnapshot: {
        pairKey: requestPair,
        state: { loading: false },
      },
      permissionSnapshot: {
        pairKey: requestPair,
        state: { kind: "loading" },
      },
      listSnapshot: { pairKey: requestPair, state: initialListState },
    });
  }, [
    setCreateSelection,
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
      .listTenantRoles(tenantId, {
        includeArchived: true,
        signal: controller.signal,
      })
      .then((page) => {
        if (
          !controller.signal.aborted &&
          requestPairRef.current === requestPair &&
          authorityReadyRef.current
        ) {
          assertTenantRoleSummaries(page.items, tenantId);
          setListSnapshot({
            pairKey: requestPair,
            state: {
              items: mergeTenantRoles([], page.items),
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
              "The tenant role inventory could not be loaded.",
            ),
          },
        });
      });

    return () => controller.abort();
  }, [
    setPaginationSnapshot,
    setListSnapshot,
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
    if (!tenantId || !authorityReady || !canManage) {
      setPermissionSnapshot({
        pairKey: requestPair,
        state: { kind: "loading" },
      });
      return undefined;
    }
    const controller = new AbortController();
    setPermissionSnapshot({
      pairKey: requestPair,
      state: { kind: "loading" },
    });

    void loadPermissionCatalog(api, tenantId, controller.signal)
      .then((items) => {
        if (
          !controller.signal.aborted &&
          requestPairRef.current === requestPair &&
          authorityReadyRef.current
        ) {
          setPermissionSnapshot({
            pairKey: requestPair,
            state: { items, kind: "ready" },
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
        setPermissionSnapshot({
          pairKey: requestPair,
          state: {
            kind: "error",
            message: describePhaseTwoError(
              caught,
              "The permission catalog could not be loaded, so role policy editing is unavailable.",
            ),
          },
        });
      });

    return () => controller.abort();
  }, [
    setPermissionSnapshot,
    api,
    authorityReady,
    canManage,
    clearSession,
    requestPair,
    session.id,
    tenantId,
  ]);

  useEffect(() => {
    createGenerationRef.current += 1;
    setCreateSelection(null);
    detailGenerationRef.current += 1;
    detailRequestRef.current?.controller.abort();
    detailRequestRef.current = null;
    setRoleSelection(null);
    return () => {
      createGenerationRef.current += 1;
      detailGenerationRef.current += 1;
      detailRequestRef.current?.controller.abort();
      detailRequestRef.current = null;
      paginationGenerationRef.current += 1;
      paginationRequestRef.current?.controller.abort();
      paginationRequestRef.current = null;
    };
  }, [setCreateSelection, setRoleSelection, requestPair]);

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
      const page = await api.listTenantRoles(tenantId, {
        after: cursor,
        includeArchived: true,
        signal: controller.signal,
      });
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
      if (page.nextCursor === cursor) {
        throw new Error("The role cursor did not advance.");
      }
      assertTenantRoleSummaries(page.items, tenantId);
      setListSnapshot((current) => {
        if (
          current.pairKey !== expectedPair ||
          current.state.kind !== "ready" ||
          current.state.nextCursor !== cursor
        ) {
          return current;
        }
        const merged = tryMergeTenantRoles(current.state.items, page.items);
        return merged.ok
          ? {
              pairKey: expectedPair,
              state: {
                items: merged.items,
                kind: "ready",
                ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
              },
            }
          : {
              pairKey: expectedPair,
              state: {
                kind: "error",
                message:
                  "The role inventory returned conflicting representations at the same version. Reload the inventory before acting.",
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
            "More roles could not be loaded.",
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

  const openRole = useCallback(
    (roleId: string): void => {
      if (!tenantId || !authorityReadyRef.current) {
        return;
      }
      const expectedPair = requestPair;
      detailRequestRef.current?.controller.abort();
      const controller = new AbortController();
      const generation = detailGenerationRef.current + 1;
      detailGenerationRef.current = generation;
      detailRequestRef.current = {
        controller,
        generation,
        pairKey: expectedPair,
        roleId,
      };
      updateWorkspaceState({
        roleSelection: { generation, pairKey: expectedPair, roleId },
        detailSnapshot: {
          pairKey: expectedPair,
          roleId,
          state: { kind: "loading" },
        },
      });
      void api
        .getTenantRole(tenantId, roleId, controller.signal)
        .then((role) => {
          if (
            requestPairRef.current !== expectedPair ||
            !authorityReadyRef.current ||
            !isCurrentRoleDetailRequest(
              detailRequestRef.current,
              expectedPair,
              roleId,
              generation,
            )
          ) {
            return;
          }
          assertVersionedTenantRole(role, tenantId, roleId);
          detailRequestRef.current = null;
          setDetailSnapshot({
            pairKey: expectedPair,
            roleId,
            state: { kind: "ready", role },
          });
        })
        .catch((caught: unknown) => {
          if (
            controller.signal.aborted ||
            requestPairRef.current !== expectedPair ||
            !authorityReadyRef.current ||
            !isCurrentRoleDetailRequest(
              detailRequestRef.current,
              expectedPair,
              roleId,
              generation,
            )
          ) {
            return;
          }
          detailRequestRef.current = null;
          if (caught instanceof PhaseTwoApiError && caught.status === 401) {
            clearSession(session.id);
            return;
          }
          if (caught instanceof PhaseTwoApiError && caught.status === 403) {
            setDetailSnapshot({
              pairKey: expectedPair,
              roleId,
              state: {
                kind: "error",
                message: "The server denied access to this role.",
              },
            });
            return;
          }
          setDetailSnapshot({
            pairKey: expectedPair,
            roleId,
            state: {
              kind: "error",
              message: describePhaseTwoError(
                caught,
                "The role could not be loaded.",
              ),
            },
          });
        });
    },
    [setDetailSnapshot, api, clearSession, requestPair, session.id, tenantId],
  );

  const closeRole = useCallback((): void => {
    detailGenerationRef.current += 1;
    detailRequestRef.current?.controller.abort();
    detailRequestRef.current = null;
    setRoleSelection(null);
  }, [setRoleSelection]);

  function openCreateRole(): void {
    if (!authorityReadyRef.current) {
      return;
    }
    const generation = createGenerationRef.current + 1;
    createGenerationRef.current = generation;
    setCreateSelection({ generation, pairKey: requestPair });
  }

  function closeCreateRole(): void {
    createGenerationRef.current += 1;
    setCreateSelection(null);
  }

  function replaceSummary(role: TenantRoleView): void {
    if (!authorityReadyRef.current) {
      return;
    }
    const expectedPair = requestPair;
    setListSnapshot((current) => {
      if (current.pairKey !== expectedPair || current.state.kind !== "ready") {
        return current;
      }
      const merged = tryMergeTenantRoles(current.state.items, [
        toRoleSummary(role),
      ]);
      return merged.ok
        ? {
            pairKey: expectedPair,
            state: {
              ...current.state,
              items: merged.items,
            },
          }
        : {
            pairKey: expectedPair,
            state: {
              kind: "error",
              message:
                "The role inventory returned conflicting representations at the same version. Reload the inventory before acting.",
            },
          };
    });
  }

  const tableData = useMemo(
    () => (listState.kind === "ready" ? [...listState.items] : []),
    [listState],
  );
  const columns = useMemo(
    () =>
      roleColumnHelper.columns([
        roleColumnHelper.accessor("name", {
          cell: ({ row }) => (
            <span className="role-name-cell">
              <strong>{row.original.name}</strong>
              <small>{row.original.key}</small>
            </span>
          ),
          header: "Role",
        }),
        roleColumnHelper.accessor("system", {
          cell: ({ getValue }) =>
            getValue() ? <Badge variant="secondary">Built-in</Badge> : "Custom",
          header: "Origin",
        }),
        roleColumnHelper.accessor("principalKind", {
          cell: ({ getValue }) =>
            getValue() === "service_account" ? "Machine" : "Human",
          header: "Principal",
        }),
        roleColumnHelper.accessor("archived", {
          cell: ({ getValue }) => (
            <Badge variant={getValue() ? "outline" : "secondary"}>
              {getValue() ? "Archived" : "Active"}
            </Badge>
          ),
          header: "State",
        }),
        roleColumnHelper.accessor("updatedAt", {
          cell: ({ getValue }) => formatDate(getValue()),
          header: "Updated",
        }),
        roleColumnHelper.display({
          cell: ({ row }) => (
            <Button
              type="button"
              size="sm"
              variant="ghost"
              aria-label={`View role ${row.original.name} (${row.original.key})`}
              onClick={() => openRole(row.original.id)}
            >
              <Eye aria-hidden="true" /> View
            </Button>
          ),
          header: "Actions",
          id: "actions",
        }),
      ]),
    [openRole],
  );
  const table = useTable({
    columns,
    data: tableData,
    features: roleTableFeatures,
    getRowId: (row) => row.id,
  });

  if (listState.kind === "forbidden") {
    return {
      kind: "content" as const,
      content: <ServerDenied resource="the tenant role inventory" />,
    };
  }

  if (listState.kind === "inactive") {
    return {
      kind: "content" as const,
      content: (
        <TenantRequiredPage
          label="Tenant authorization"
          title="Select a tenant to inspect roles."
        >
          Role policy always requires an explicit active tenant context.
        </TenantRequiredPage>
      ),
    };
  }

  return {
    kind: "ready" as const,
    data: {
      activeCreateSelection,
      api,
      authority,
      authorityReadyRef,
      canManage,
      closeCreateRole,
      closeRole,
      createGenerationRef,
      createOpen,
      detailGenerationRef,
      detailState,
      isLoadingMore,
      listState,
      loadMore,
      openCreateRole,
      paginationError,
      permissionState,
      replaceSummary,
      requestPair,
      requestPairRef,
      selectedRole,
      selectedRoleId,
      session,
      setLoadAttempt,
      table,
      tenantId,
    },
  };
}

function TenantRolesPageView({
  model,
}: {
  model: Extract<
    ReturnType<typeof useTenantRolesPageModel>,
    { kind: "ready" }
  >["data"];
}): React.JSX.Element {
  return <RoleWorkspace model={model} />;
}

function CreateRoleDialog({
  api,
  csrfToken,
  delegation,
  onAuthorityChanged,
  onCreated,
  onOpenChange,
  open,
  permissions,
  tenantId,
}: {
  api: PhaseTwoApi;
  csrfToken: string;
  delegation: readonly EffectiveTenantDelegationView[];
  onAuthorityChanged: () => void;
  onCreated: (role: TenantRoleView) => void;
  onOpenChange: (open: boolean) => void;
  open: boolean;
  permissions: readonly TenantPermissionView[];
  tenantId: string;
}): React.JSX.Element {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent
        className="role-dialog"
        aria-describedby="create-role-description"
      >
        <DialogHeader>
          <DialogTitle>Create custom role</DialogTitle>
          <DialogDescription id="create-role-description">
            The metadata and complete policy are created atomically.
          </DialogDescription>
        </DialogHeader>
        <RoleEditorForm
          api={api}
          csrfToken={csrfToken}
          delegation={delegation}
          onAuthorityChanged={onAuthorityChanged}
          onSaved={(role) => onCreated(role.value)}
          permissions={permissions}
          tenantId={tenantId}
        />
      </DialogContent>
    </Dialog>
  );
}

function RoleDetailDialog(props: {
  api: PhaseTwoApi;
  canManage: boolean;
  csrfToken: string;
  delegation: readonly EffectiveTenantDelegationView[];
  detailState: DetailState;
  onAuthorityChanged: () => void;
  onArchived: () => void;
  onChanged: (role: TenantRoleView) => void;
  onOpenChange: (open: boolean) => void;
  permissions: readonly TenantPermissionView[];
  tenantId: string;
}): React.JSX.Element {
  const model = useRoleDetailDialogModel(props);
  return <RoleDetailDialogView model={model.data} />;
}

function useRoleDetailDialogModel({
  api,
  canManage,
  csrfToken,
  delegation,
  detailState,
  onAuthorityChanged,
  onArchived,
  onChanged,
  onOpenChange,
  permissions,
  tenantId,
}: {
  api: PhaseTwoApi;
  canManage: boolean;
  csrfToken: string;
  delegation: readonly EffectiveTenantDelegationView[];
  detailState: DetailState;
  onAuthorityChanged: () => void;
  onArchived: () => void;
  onChanged: (role: TenantRoleView) => void;
  onOpenChange: (open: boolean) => void;
  permissions: readonly TenantPermissionView[];
  tenantId: string;
}) {
  const { clearSession, session } = useSession();
  const [workspaceState, updateWorkspaceState] = useReducer(
    reduceWorkspaceState<RoleDetailDialogState>,
    undefined,
    (): RoleDetailDialogState => ({
      editing: false,
      working: detailState.kind === "ready" ? detailState.role : null,
      archiveConfirmation: false,
      archiveError: null,
      isArchiving: false,
    }),
  );
  const { editing, working, archiveConfirmation, archiveError, isArchiving } =
    workspaceState;
  const {
    setEditing,
    setWorking,
    setArchiveConfirmation,
    setArchiveError,
    setIsArchiving,
  } = useMemo(
    () => ({
      setEditing: (
        value: React.SetStateAction<RoleDetailDialogState["editing"]>,
      ) => updateWorkspaceState({ editing: value }),
      setWorking: (
        value: React.SetStateAction<RoleDetailDialogState["working"]>,
      ) => updateWorkspaceState({ working: value }),
      setArchiveConfirmation: (
        value: React.SetStateAction<
          RoleDetailDialogState["archiveConfirmation"]
        >,
      ) => updateWorkspaceState({ archiveConfirmation: value }),
      setArchiveError: (
        value: React.SetStateAction<RoleDetailDialogState["archiveError"]>,
      ) => updateWorkspaceState({ archiveError: value }),
      setIsArchiving: (
        value: React.SetStateAction<RoleDetailDialogState["isArchiving"]>,
      ) => updateWorkspaceState({ isArchiving: value }),
    }),
    [updateWorkspaceState],
  );

  const mountedRef = useRef(false);
  const workingRef = useRef(working);
  useLayoutEffect(() => {
    workingRef.current = working;
  });
  const archiveGenerationRef = useRef(0);
  const refreshRequestRef = useRef<AbortController | null>(null);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      archiveGenerationRef.current += 1;
      refreshRequestRef.current?.abort();
      refreshRequestRef.current = null;
    };
  }, []);

  useEffect(() => {
    updateWorkspaceState({
      working: detailState.kind === "ready" ? detailState.role : null,
      editing: false,
      archiveConfirmation: false,
      archiveError: null,
    });
  }, [detailState]);

  async function archiveRole(): Promise<void> {
    if (!working) {
      return;
    }
    const rejected = working;
    const generation = archiveGenerationRef.current + 1;
    archiveGenerationRef.current = generation;
    updateWorkspaceState({ archiveError: null, isArchiving: true });
    try {
      await api.archiveTenantRole(
        csrfToken,
        tenantId,
        rejected.value.id,
        rejected.etag,
      );
      if (!mountedRef.current || archiveGenerationRef.current !== generation) {
        return;
      }
      onAuthorityChanged();
      onArchived();
    } catch (caught) {
      if (!mountedRef.current || archiveGenerationRef.current !== generation) {
        return;
      }
      if (caught instanceof PhaseTwoApiError && caught.status === 401) {
        clearSession(session.id);
        return;
      }
      if (caught instanceof PhaseTwoApiError && caught.status === 412) {
        refreshRequestRef.current?.abort();
        const controller = new AbortController();
        refreshRequestRef.current = controller;
        try {
          const refreshed = await api.getTenantRole(
            tenantId,
            rejected.value.id,
            controller.signal,
          );
          if (
            !mountedRef.current ||
            archiveGenerationRef.current !== generation ||
            controller.signal.aborted ||
            refreshRequestRef.current !== controller
          ) {
            return;
          }
          assertVersionedTenantRole(refreshed, tenantId, rejected.value.id);
          const current = workingRef.current;
          if (!current) {
            return;
          }
          const reconciled = reconcileRefreshedRole(
            current,
            rejected,
            refreshed,
          );
          workingRef.current = reconciled;
          setWorking(reconciled);
          onChanged(reconciled.value);
          setArchiveError(
            `This role changed on the server. We reloaded version ${reconciled.value.version} in place; review it, then confirm archive again.`,
          );
        } catch (refreshError) {
          if (
            mountedRef.current &&
            archiveGenerationRef.current === generation &&
            !controller.signal.aborted
          ) {
            setArchiveError(
              `This role changed on the server, but its exact current representation could not be reconciled. ${describePhaseTwoError(
                refreshError,
                "Retry to reload the current role before archiving.",
              )}`,
            );
          }
        } finally {
          if (refreshRequestRef.current === controller) {
            refreshRequestRef.current = null;
          }
        }
        return;
      }
      setArchiveError(
        describePhaseTwoError(caught, "The role was not archived."),
      );
    } finally {
      if (mountedRef.current && archiveGenerationRef.current === generation) {
        setIsArchiving(false);
      }
    }
  }

  const role = working?.value;
  return {
    kind: "ready" as const,
    data: {
      api,
      archiveConfirmation,
      archiveError,
      archiveRole,
      canManage,
      csrfToken,
      delegation,
      detailState,
      editing,
      isArchiving,
      onAuthorityChanged,
      onChanged,
      onOpenChange,
      permissions,
      role,
      setArchiveConfirmation,
      setEditing,
      setWorking,
      tenantId,
      updateWorkspaceState,
      working,
    },
  };
}

function RoleDetailDialogView({
  model,
}: {
  model: Extract<
    ReturnType<typeof useRoleDetailDialogModel>,
    { kind: "ready" }
  >["data"];
}): React.JSX.Element {
  const {
    api,
    csrfToken,
    delegation,
    detailState,
    editing,
    onAuthorityChanged,
    onChanged,
    onOpenChange,
    permissions,
    role,
    setEditing,
    setWorking,
    tenantId,
    updateWorkspaceState,
    working,
  } = model;
  return (
    <Dialog open onOpenChange={onOpenChange}>
      <DialogContent className="role-dialog">
        <DialogHeader>
          <DialogTitle>
            {editing ? "Edit custom role" : (role?.name ?? "Role details")}
          </DialogTitle>
          <DialogDescription>
            {editing
              ? "Changes use the strong version returned with this role."
              : "Live role metadata and its complete exact-scope policy."}
          </DialogDescription>
        </DialogHeader>
        {detailState.kind === "loading" ? <RoleListSkeleton /> : null}
        {detailState.kind === "error" ? (
          <FocusedError message={detailState.message} />
        ) : null}
        {role && editing ? (
          <RoleEditorForm
            api={api}
            csrfToken={csrfToken}
            delegation={delegation}
            initial={working}
            onAuthorityChanged={onAuthorityChanged}
            onCancel={() => setEditing(false)}
            onProgress={(next) => {
              setWorking(next);
              onChanged(next.value);
            }}
            onSaved={(next) => {
              updateWorkspaceState({ working: next, editing: false });
              onChanged(next.value);
            }}
            permissions={permissions}
            tenantId={tenantId}
          />
        ) : null}
        <RoleReadonlyDetails model={model} />
      </DialogContent>
    </Dialog>
  );
}

function RoleEditorForm(props: {
  api: PhaseTwoApi;
  csrfToken: string;
  delegation: readonly EffectiveTenantDelegationView[];
  initial?: VersionedView<TenantRoleView> | null;
  onAuthorityChanged: () => void;
  onCancel?: () => void;
  onProgress?: (role: VersionedView<TenantRoleView>) => void;
  onSaved: (role: VersionedView<TenantRoleView>) => void;
  permissions: readonly TenantPermissionView[];
  tenantId: string;
}): React.JSX.Element {
  const model = useRoleEditorFormModel(props);
  return <RoleEditorFormView model={model.data} />;
}

function useRoleEditorFormModel({
  api,
  csrfToken,
  delegation,
  initial,
  onAuthorityChanged,
  onCancel,
  onProgress,
  onSaved,
  permissions,
  tenantId,
}: {
  api: PhaseTwoApi;
  csrfToken: string;
  delegation: readonly EffectiveTenantDelegationView[];
  initial?: VersionedView<TenantRoleView> | null;
  onAuthorityChanged: () => void;
  onCancel?: () => void;
  onProgress?: (role: VersionedView<TenantRoleView>) => void;
  onSaved: (role: VersionedView<TenantRoleView>) => void;
  permissions: readonly TenantPermissionView[];
  tenantId: string;
}) {
  const { clearSession, session } = useSession();
  const formId = useId();
  const [workspaceState, updateWorkspaceState] = useReducer(
    reduceWorkspaceState<RoleEditorFormState>,
    undefined,
    (): RoleEditorFormState => ({
      base: initial ?? null,
      formError: null,
      partiallySaved: false,
      isSaving: false,
    }),
  );
  const { base, formError, partiallySaved, isSaving } = workspaceState;
  const { setBase, setFormError, setPartiallySaved, setIsSaving } = useMemo(
    () => ({
      setBase: (value: React.SetStateAction<RoleEditorFormState["base"]>) =>
        updateWorkspaceState({ base: value }),
      setFormError: (
        value: React.SetStateAction<RoleEditorFormState["formError"]>,
      ) => updateWorkspaceState({ formError: value }),
      setPartiallySaved: (
        value: React.SetStateAction<RoleEditorFormState["partiallySaved"]>,
      ) => updateWorkspaceState({ partiallySaved: value }),
      setIsSaving: (
        value: React.SetStateAction<RoleEditorFormState["isSaving"]>,
      ) => updateWorkspaceState({ isSaving: value }),
    }),
    [updateWorkspaceState],
  );

  const baseRef = useRef(base);
  useLayoutEffect(() => {
    baseRef.current = base;
  });
  const mountedRef = useRef(false);
  const operationGenerationRef = useRef(0);
  const refreshRequestRef = useRef<AbortController | null>(null);
  const idempotencyBindingRef = useRef<{
    fingerprint: string;
    key: string;
  } | null>(null);
  const matrix = useMemo(
    () => buildRoleMatrix(permissions, initial?.value.policy),
    [initial, permissions],
  );
  const { control, getValues, handleSubmit, register, reset, setValue } =
    useForm<RoleFormValues>({
      defaultValues: {
        description: initial?.value.description ?? "",
        key: initial?.value.key ?? "",
        name: initial?.value.name ?? "",
        tuples: matrix,
      },
    });

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      operationGenerationRef.current += 1;
      refreshRequestRef.current?.abort();
      refreshRequestRef.current = null;
    };
  }, []);

  function operationIsCurrent(generation: number): boolean {
    return mountedRef.current && operationGenerationRef.current === generation;
  }

  function commitBase(
    next: VersionedView<TenantRoleView>,
    notifyProgress: boolean,
  ): void {
    baseRef.current = next;
    setBase(next);
    if (notifyProgress) {
      onProgress?.(next);
    }
  }

  async function refreshRejectedRole(
    rejected: VersionedView<TenantRoleView>,
    generation: number,
  ): Promise<VersionedView<TenantRoleView> | null> {
    refreshRequestRef.current?.abort();
    const controller = new AbortController();
    refreshRequestRef.current = controller;
    try {
      const refreshed = await api.getTenantRole(
        tenantId,
        rejected.value.id,
        controller.signal,
      );
      if (
        !operationIsCurrent(generation) ||
        controller.signal.aborted ||
        refreshRequestRef.current !== controller
      ) {
        return null;
      }
      assertVersionedTenantRole(refreshed, tenantId, rejected.value.id);
      const current = baseRef.current;
      if (!current) {
        throw new Error(
          "The role editor no longer has a current base version.",
        );
      }
      const reconciled = reconcileRefreshedRole(current, rejected, refreshed);
      reset(
        {
          description: reconciled.value.description ?? "",
          key: reconciled.value.key,
          name: reconciled.value.name,
          tuples: buildRoleMatrix(permissions, reconciled.value.policy),
        },
        { keepDirtyValues: true },
      );
      commitBase(reconciled, true);
      return reconciled;
    } finally {
      if (refreshRequestRef.current === controller) {
        refreshRequestRef.current = null;
      }
    }
  }

  const submit = handleSubmit(async (rawValues) => {
    const parsed = roleFormSchema.safeParse(rawValues);
    if (!parsed.success) {
      setFormError(
        parsed.error.issues[0]?.message ?? "Review the role fields.",
      );
      return;
    }
    const values = parsed.data;
    const policy = policyFromMatrix(values.tuples);
    const startingBase = baseRef.current;
    const policyChanged =
      !startingBase || !samePolicy(policy, startingBase.value.policy);
    if (policyChanged) {
      const invalidTuple = values.tuples.find(
        (tuple) =>
          (tuple.granted || tuple.delegable) &&
          (!isCatalogTuple(permissions, tuple.permissionKey, tuple.scope) ||
            !containsDelegation(delegation, tuple.permissionKey, tuple.scope)),
      );
      if (invalidTuple) {
        setFormError(
          "The selected policy exceeds the live permission catalog or your effective delegation ceiling.",
        );
        return;
      }
    }
    updateWorkspaceState({
      formError: null,
      partiallySaved: false,
      isSaving: true,
    });
    const generation = operationGenerationRef.current + 1;
    operationGenerationRef.current = generation;
    let metadataSaved = false;
    let current = startingBase;
    let rejected: VersionedView<TenantRoleView> | null = null;
    try {
      if (!current) {
        const input = {
          ...(values.description.trim()
            ? { description: values.description.trim() }
            : {}),
          key: values.key,
          name: values.name,
          policy,
        };
        const created = await api.createTenantRole(
          csrfToken,
          tenantId,
          idempotencyKeyForPayload(idempotencyBindingRef, {
            input,
            tenantId,
          }),
          input,
        );
        if (!operationIsCurrent(generation)) {
          return;
        }
        assertVersionedTenantRole(created, tenantId, created.value.id);
        onAuthorityChanged();
        onSaved(created);
        return;
      }

      const description = values.description.trim();
      if (
        values.name !== current.value.name ||
        description !== (current.value.description ?? "")
      ) {
        rejected = current;
        const updated = await api.updateTenantRole(
          csrfToken,
          tenantId,
          current.value.id,
          current.etag,
          { description, name: values.name },
        );
        if (!operationIsCurrent(generation)) {
          return;
        }
        assertVersionedTenantRole(updated, tenantId, current.value.id);
        current = reconcileRefreshedRole(current, current, updated);
        commitBase(current, true);
        metadataSaved = true;
      }
      if (policyChanged) {
        rejected = current;
        const updated = await api.replaceTenantRolePolicy(
          csrfToken,
          tenantId,
          current.value.id,
          current.etag,
          policy,
        );
        if (!operationIsCurrent(generation)) {
          return;
        }
        assertVersionedTenantRole(updated, tenantId, current.value.id);
        current = reconcileRefreshedRole(current, current, updated);
        commitBase(current, false);
        onAuthorityChanged();
      }
      if (!operationIsCurrent(generation)) {
        return;
      }
      onSaved(current);
    } catch (caught) {
      if (!operationIsCurrent(generation)) {
        return;
      }
      if (caught instanceof PhaseTwoApiError && caught.status === 401) {
        clearSession(session.id);
        return;
      }
      if (
        caught instanceof PhaseTwoApiError &&
        caught.status === 412 &&
        rejected
      ) {
        try {
          const refreshed = await refreshRejectedRole(rejected, generation);
          if (!refreshed || !operationIsCurrent(generation)) {
            return;
          }
          if (metadataSaved && policyChanged) {
            updateWorkspaceState({
              partiallySaved: true,
              formError: `Role metadata was saved, but the policy met a newer server version. We reloaded role and policy version ${refreshed.value.version} in place; your edits are preserved for review and retry.`,
            });
          } else {
            setFormError(
              `This role changed on the server. We reloaded role and policy version ${refreshed.value.version} in place; your edits are preserved for review and retry.`,
            );
          }
        } catch (refreshError) {
          if (!operationIsCurrent(generation)) {
            return;
          }
          if (
            refreshError instanceof PhaseTwoApiError &&
            refreshError.status === 401
          ) {
            clearSession(session.id);
            return;
          }
          if (metadataSaved && policyChanged) {
            setPartiallySaved(true);
          }
          setFormError(
            `This role changed on the server, but its exact current role and policy could not be reconciled. ${describePhaseTwoError(
              refreshError,
              "Your edits are preserved; retry to reload the current version.",
            )}`,
          );
        }
        return;
      }
      if (metadataSaved && policyChanged && current) {
        updateWorkspaceState({
          partiallySaved: true,
          formError: `Role metadata was saved as version ${current.value.version}, but the policy was not updated. ${describePhaseTwoError(
            caught,
            "The policy request failed.",
          )} Your policy input is preserved and a retry will use the saved metadata version.`,
        });
      } else {
        setFormError(
          describePhaseTwoError(
            caught,
            "The role was not saved. Your input has been preserved.",
          ),
        );
      }
    } finally {
      if (operationIsCurrent(generation)) {
        // react-doctor-disable-next-line no-loading-flag-reset-outside-finally -- The owning request clears this flag in finally; the generation guard protects newer requests.
        setIsSaving(false);
      }
    }
  });

  return {
    kind: "ready" as const,
    data: {
      base,
      control,
      delegation,
      formError,
      formId,
      getValues,
      isSaving,
      matrix,
      onCancel,
      partiallySaved,
      permissions,
      register,
      setValue,
      submit,
    },
  };
}

function RoleEditorFormView({
  model,
}: {
  model: Extract<
    ReturnType<typeof useRoleEditorFormModel>,
    { kind: "ready" }
  >["data"];
}): React.JSX.Element {
  return <RolePolicyEditor model={model} />;
}

function PolicyTupleRow({
  control,
  delegation,
  description,
  formId,
  index,
  setValue,
  tuple,
}: {
  control: Control<RoleFormValues>;
  delegation: readonly EffectiveTenantDelegationView[];
  description: string;
  formId: string;
  index: number;
  setValue: UseFormSetValue<RoleFormValues>;
  tuple: RoleFormValues["tuples"][number];
}): React.JSX.Element {
  const withinCeiling = containsDelegation(
    delegation,
    tuple.permissionKey,
    tuple.scope,
  );
  const grantId = `${formId}-${tuple.permissionKey}-${tuple.scope}-grant`;
  const delegateId = `${formId}-${tuple.permissionKey}-${tuple.scope}-delegate`;
  const descriptionId = `${formId}-${tuple.permissionKey}-${tuple.scope}-description`;
  return (
    <div className="authority-matrix__row">
      <div>
        <strong>{formatPermissionKey(tuple.permissionKey)}</strong>
        <span>{formatScope(tuple.scope)}</span>
        <small id={descriptionId}>
          {description}
          {!withinCeiling ? " Outside your live delegation ceiling." : ""}
        </small>
      </div>
      <Controller
        control={control}
        name={`tuples.${index}.granted`}
        render={({ field }) => (
          <span className="matrix-check">
            <Checkbox
              id={grantId}
              aria-describedby={descriptionId}
              aria-label={`Grant ${formatPermissionKey(tuple.permissionKey)} at ${formatScope(tuple.scope)} scope`}
              checked={field.value}
              disabled={!withinCeiling && !field.value}
              onCheckedChange={(checked) => {
                const selected = checked === true;
                field.onChange(selected);
                if (!selected) {
                  setValue(`tuples.${index}.delegable`, false, {
                    shouldDirty: true,
                  });
                }
              }}
            />
            <label htmlFor={grantId}>Grant</label>
          </span>
        )}
      />
      <Controller
        control={control}
        name={`tuples.${index}.delegable`}
        render={({ field }) => (
          <Controller
            control={control}
            name={`tuples.${index}.granted`}
            render={({ field: grantField }) => (
              <span className="matrix-check">
                <Checkbox
                  id={delegateId}
                  aria-describedby={descriptionId}
                  aria-label={`Delegate ${formatPermissionKey(tuple.permissionKey)} at ${formatScope(tuple.scope)} scope`}
                  checked={field.value}
                  disabled={
                    !grantField.value || (!withinCeiling && !field.value)
                  }
                  onCheckedChange={(checked) =>
                    field.onChange(checked === true)
                  }
                />
                <label htmlFor={delegateId}>Delegate</label>
              </span>
            )}
          />
        )}
      />
    </div>
  );
}

function RolePolicySummary({
  policy,
}: {
  policy: TenantRolePolicyView;
}): React.JSX.Element {
  const delegated = new Set(
    policy.delegationCeiling.map((tuple) =>
      tupleKey(tuple.permissionKey, tuple.scope),
    ),
  );
  return (
    <section
      className="role-policy-summary"
      aria-labelledby="role-policy-heading"
    >
      <h3 id="role-policy-heading">Exact policy</h3>
      {policy.permissions.length === 0 ? (
        <p>No permission tuples are granted.</p>
      ) : (
        <ul>
          {policy.permissions.map((tuple) => (
            <li key={tupleKey(tuple.permissionKey, tuple.scope)}>
              <span>
                <strong>{formatPermissionKey(tuple.permissionKey)}</strong>
                <small>{formatScope(tuple.scope)}</small>
              </span>
              {delegated.has(tupleKey(tuple.permissionKey, tuple.scope)) ? (
                <Badge variant="outline">Delegable</Badge>
              ) : null}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function RoleListSkeleton(): React.JSX.Element {
  return (
    <div className="tenant-list-skeleton" aria-label="Loading tenant roles">
      <span />
      <span />
      <span />
    </div>
  );
}

async function loadPermissionCatalog(
  api: PhaseTwoApi,
  tenantId: string,
  signal: AbortSignal,
): Promise<readonly TenantPermissionView[]> {
  let cursor: string | undefined;
  let items: readonly TenantPermissionView[] = [];
  const seenCursors = new Set<string>();
  for (let pageCount = 0; pageCount < 20; pageCount += 1) {
    // oxlint-disable-next-line no-await-in-loop -- Each opaque cursor is returned by the preceding page.
    const page = await api.listTenantPermissions(tenantId, cursor, signal);
    items = mergePermissions(items, page.items);
    if (!page.nextCursor) {
      return items;
    }
    if (seenCursors.has(page.nextCursor)) {
      throw new Error("The permission cursor entered a cycle.");
    }
    seenCursors.add(page.nextCursor);
    cursor = page.nextCursor;
  }
  throw new Error("The permission catalog exceeded the safe page limit.");
}

function mergePermissions(
  current: readonly TenantPermissionView[],
  incoming: readonly TenantPermissionView[],
): readonly TenantPermissionView[] {
  const byKey = new Map(
    current.map((permission) => [permission.key, permission]),
  );
  for (const permission of incoming) {
    byKey.set(permission.key, permission);
  }
  return tenantPermissionKeys.flatMap((key) => {
    const permission = byKey.get(key);
    return permission ? [permission] : [];
  });
}

function buildRoleMatrix(
  permissions: readonly TenantPermissionView[],
  policy?: TenantRolePolicyView,
): RoleFormValues["tuples"] {
  const granted = new Set(
    policy?.permissions.map((tuple) =>
      tupleKey(tuple.permissionKey, tuple.scope),
    ) ?? [],
  );
  const delegable = new Set(
    policy?.delegationCeiling.map((tuple) =>
      tupleKey(tuple.permissionKey, tuple.scope),
    ) ?? [],
  );
  return permissions.flatMap((permission) =>
    tenantAuthorizationScopes.flatMap((scope) => {
      if (!permission.allowedScopes.includes(scope)) {
        return [];
      }
      const key = tupleKey(permission.key, scope);
      return [
        {
          delegable: delegable.has(key),
          granted: granted.has(key),
          permissionKey: permission.key,
          scope,
        },
      ];
    }),
  );
}

function policyFromMatrix(
  tuples: RoleFormValues["tuples"],
): TenantRolePolicyView {
  const permissions: TenantRolePolicyView["permissions"][number][] = [];
  const delegationCeiling: TenantRolePolicyView["delegationCeiling"][number][] =
    [];
  for (const tuple of tuples) {
    if (!tuple.granted) continue;
    const value = { permissionKey: tuple.permissionKey, scope: tuple.scope };
    permissions.push(value);
    if (tuple.delegable) delegationCeiling.push(value);
  }
  return { delegationCeiling, permissions };
}

function samePolicy(
  first: TenantRolePolicyView,
  second: TenantRolePolicyView,
): boolean {
  return (
    tupleSet(first.permissions) === tupleSet(second.permissions) &&
    tupleSet(first.delegationCeiling) === tupleSet(second.delegationCeiling)
  );
}

function tupleSet(
  tuples: readonly { permissionKey: string; scope: string }[],
): string {
  return tuples
    .map((tuple) => tupleKey(tuple.permissionKey, tuple.scope))
    .toSorted()
    .join("|");
}

function containsDelegation(
  delegation: readonly EffectiveTenantDelegationView[],
  permissionKey: TenantRolePolicyView["permissions"][number]["permissionKey"],
  scope: TenantRolePolicyView["permissions"][number]["scope"],
): boolean {
  return delegation.some(
    (entry) => entry.permissionKey === permissionKey && entry.scope === scope,
  );
}

function isCatalogTuple(
  permissions: readonly TenantPermissionView[],
  permissionKey: TenantRolePolicyView["permissions"][number]["permissionKey"],
  scope: TenantRolePolicyView["permissions"][number]["scope"],
): boolean {
  return permissions.some(
    (permission) =>
      permission.key === permissionKey &&
      permission.allowedScopes.includes(scope),
  );
}

function tupleKey(permissionKey: string, scope: string): string {
  return `${permissionKey}:${scope}`;
}

function toRoleSummary(role: TenantRoleView): TenantRoleSummaryView {
  const { policy: _policy, ...summary } = role;
  return summary;
}

function deriveInitialRoleListState(
  tenantId: string | undefined,
  status: string,
  message: string | undefined,
  canRead: boolean,
): RoleListState {
  if (!tenantId) {
    return { kind: "inactive" };
  }
  if (status === "error") {
    return {
      kind: "error",
      message:
        message ??
        "Live tenant authority is unavailable. Role access stays closed.",
    };
  }
  if (status === "forbidden" || (status === "ready" && !canRead)) {
    return { kind: "forbidden" };
  }
  return { kind: "loading" };
}

function assertTenantRoleSummaries(
  roles: readonly TenantRoleSummaryView[],
  tenantId: string,
): void {
  if (
    roles.some(
      (role) =>
        role.tenantId !== tenantId ||
        (role.principalKind !== "human" &&
          role.principalKind !== "service_account") ||
        !validRoleVersion(role.version),
    )
  ) {
    throw new Error("The role response escaped the active tenant or version.");
  }
}

function assertVersionedTenantRole(
  role: VersionedView<TenantRoleView>,
  tenantId: string,
  roleId: string,
): void {
  const etag = roleEntityTagPattern.exec(role.etag);
  if (
    role.value.tenantId !== tenantId ||
    role.value.id !== roleId ||
    (role.value.principalKind !== "human" &&
      role.value.principalKind !== "service_account") ||
    !validRoleVersion(role.value.version) ||
    !etag ||
    etag[1] !== String(role.value.version)
  ) {
    throw new Error(
      "The role response did not match the requested tenant role and strong version.",
    );
  }
}

function roleRefreshAdvanced(
  rejected: VersionedView<TenantRoleView>,
  candidate: VersionedView<TenantRoleView>,
): boolean {
  return (
    candidate.value.version > rejected.value.version ||
    (candidate.value.version === rejected.value.version &&
      candidate.etag !== rejected.etag)
  );
}

function reconcileRefreshedRole(
  current: VersionedView<TenantRoleView>,
  rejected: VersionedView<TenantRoleView>,
  candidate: VersionedView<TenantRoleView>,
): VersionedView<TenantRoleView> {
  if (
    current.value.id !== rejected.value.id ||
    candidate.value.id !== rejected.value.id ||
    !roleRefreshAdvanced(rejected, candidate)
  ) {
    throw new Error(
      "The exact role refresh did not advance beyond the rejected representation.",
    );
  }
  if (current.value.version > candidate.value.version) {
    return current;
  }
  if (current.value.version < candidate.value.version) {
    return candidate;
  }
  if (
    current.etag === candidate.etag &&
    sameRoleRepresentation(current.value, candidate.value)
  ) {
    return current;
  }
  throw new Error(
    "The exact role refresh encountered conflicting representations at the same version.",
  );
}

function sameRoleRepresentation(
  left: TenantRoleView,
  right: TenantRoleView,
): boolean {
  return (
    sameRoleSummaryRepresentation(toRoleSummary(left), toRoleSummary(right)) &&
    samePolicy(left.policy, right.policy)
  );
}

function formatDate(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.valueOf())
    ? "Unavailable"
    : dateTimeFormatter.format(date);
}

function formatPermissionKey(value: string): string {
  return value.replaceAll(".", " · ");
}

function formatScope(value: string): string {
  return value.replaceAll("_", " ");
}

function isCurrentRoleDetailRequest(
  request: RoleDetailRequest | null,
  pairKey: string,
  roleId: string,
  generation: number,
): boolean {
  return (
    request?.pairKey === pairKey &&
    request.roleId === roleId &&
    request.generation === generation &&
    !request.controller.signal.aborted
  );
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

function RoleWorkspace({
  model,
}: {
  model: React.ComponentProps<typeof TenantRolesPageView>["model"];
}): React.ReactNode {
  const {
    canManage,
    isLoadingMore,
    listState,
    loadMore,
    openCreateRole,
    paginationError,
    permissionState,
    setLoadAttempt,
    table,
  } = model;
  return (
    <div className="content tenant-admin-page">
      <section className="page-heading" aria-labelledby="roles-page-title">
        <div>
          <p className="section-label">Authority lattice / Phase 2B</p>
          <h1 id="roles-page-title">Tenant roles</h1>
          <p>
            Inspect built-in recovery roles and manage custom policy as exact
            permission-and-scope tuples. Delegation is always narrower than the
            permission it accompanies.
          </p>
        </div>
        {canManage && permissionState.kind === "ready" ? (
          <Button type="button" onClick={openCreateRole}>
            <Plus aria-hidden="true" /> Create custom role
          </Button>
        ) : (
          <Badge variant="outline">
            <Shield aria-hidden="true" /> Read-only inventory
          </Badge>
        )}
      </section>

      {permissionState.kind === "error" && canManage ? (
        <FocusedError
          title="Policy editor unavailable"
          message={permissionState.message}
        />
      ) : null}
      {paginationError ? (
        <FocusedError
          title="More roles could not be loaded"
          message={paginationError}
        />
      ) : null}
      {listState.kind === "loading" ? <RoleListSkeleton /> : null}
      {listState.kind === "error" ? (
        <div className="tenant-admin-error">
          <FocusedError message={listState.message} />
          <Button
            type="button"
            variant="outline"
            onClick={() => setLoadAttempt((attempt) => attempt + 1)}
          >
            <RefreshCw aria-hidden="true" /> Retry role inventory
          </Button>
        </div>
      ) : null}
      {listState.kind === "ready" && listState.items.length === 0 ? (
        <div className="tenant-empty">
          <Shield aria-hidden="true" />
          <h2>No roles returned</h2>
          <p>The server returned no role definitions for this tenant.</p>
        </div>
      ) : null}
      {listState.kind === "ready" && listState.items.length > 0 ? (
        <RoleInventory
          isLoadingMore={isLoadingMore}
          listState={listState}
          loadMore={loadMore}
          table={table}
        />
      ) : null}

      <RoleCreateAction model={model} />

      <RoleDetailAction model={model} />
    </div>
  );
}

function RolePolicyEditor({
  model,
}: {
  model: React.ComponentProps<typeof RoleEditorFormView>["model"];
}): React.ReactNode {
  const {
    base,
    control,
    delegation,
    formError,
    formId,
    getValues,
    isSaving,
    matrix,
    onCancel,
    partiallySaved,
    permissions,
    register,
    setValue,
    submit,
  } = model;
  return (
    <form className="role-editor" onSubmit={submit} noValidate>
      {formError ? (
        <FocusedError
          title={partiallySaved ? "Role partially saved" : "Role not saved"}
          message={formError}
        />
      ) : null}
      <div className="role-editor__metadata">
        <FormField
          htmlFor={`${formId}-role-key`}
          label="Role key"
          hint={
            base
              ? "The stable role key cannot be changed."
              : "Use lowercase letters, numbers, and underscores."
          }
        >
          <Input
            id={`${formId}-role-key`}
            autoCapitalize="none"
            autoCorrect="off"
            disabled={isSaving}
            readOnly={Boolean(base)}
            aria-describedby={`${formId}-role-key-hint`}
            {...register("key")}
          />
        </FormField>
        <FormField htmlFor={`${formId}-role-name`} label="Role name">
          <Input
            id={`${formId}-role-name`}
            maxLength={120}
            disabled={isSaving}
            {...register("name")}
          />
        </FormField>
      </div>
      <FormField
        htmlFor={`${formId}-role-description`}
        label="Description"
        optional
      >
        <Textarea
          id={`${formId}-role-description`}
          maxLength={500}
          disabled={isSaving}
          {...register("description")}
        />
      </FormField>

      <fieldset className="authority-matrix" disabled={isSaving}>
        <legend>Exact permission and scope policy</legend>
        <p>
          Grant is authority held by the role. Delegate may only be selected
          beneath the same granted tuple and within your live ceiling.
        </p>
        <div className="authority-matrix__header" aria-hidden="true">
          <span>Permission / scope</span>
          <span>Grant</span>
          <span>Delegate</span>
        </div>
        {matrix.map((tuple, index) => (
          <PolicyTupleRow
            control={control}
            delegation={delegation}
            description={
              permissions.find(
                (permission) => permission.key === tuple.permissionKey,
              )?.description ?? ""
            }
            formId={formId}
            index={index}
            key={tupleKey(tuple.permissionKey, tuple.scope)}
            setValue={setValue}
            tuple={tuple}
          />
        ))}
      </fieldset>
      <DialogFooter>
        {onCancel ? (
          <Button
            type="button"
            variant="ghost"
            disabled={isSaving}
            onClick={onCancel}
          >
            Cancel
          </Button>
        ) : null}
        <Button
          type="submit"
          disabled={isSaving || getValues("tuples").length === 0}
        >
          {isSaving ? "Saving role…" : base ? "Save role" : "Create role"}
        </Button>
      </DialogFooter>
    </form>
  );
}

interface TenantRolesPageState {
  listSnapshot: PairSnapshot<RoleListState>;
  permissionSnapshot: PairSnapshot<PermissionState>;
  createSelection: CreateRoleSelection | null;
  loadAttempt: number;
  paginationSnapshot: PairSnapshot<PaginationState>;
  roleSelection: RoleSelection | null;
  detailSnapshot: PairSnapshot<DetailState> & { roleId: string };
}

interface RoleEditorFormState {
  base: VersionedView<TenantRoleView> | null;
  formError: string | null;
  partiallySaved: boolean;
  isSaving: boolean;
}

interface RoleDetailDialogState {
  editing: boolean;
  working: VersionedView<TenantRoleView> | null;
  archiveConfirmation: boolean;
  archiveError: string | null;
  isArchiving: boolean;
}

interface RoleInventoryProps {
  isLoadingMore: boolean;
  listState: Extract<RoleListState, { kind: "ready" }>;
  loadMore: () => Promise<void>;
  table: React.ComponentProps<typeof TenantRolesPageView>["model"]["table"];
}

function RoleInventory({
  isLoadingMore,
  listState,
  loadMore,
  table,
}: RoleInventoryProps): React.JSX.Element {
  return (
    <section
      className="authority-inventory"
      aria-labelledby="role-inventory-title"
    >
      <div className="section-heading">
        <div>
          <p className="section-label">Server inventory</p>
          <h2 id="role-inventory-title">Role definitions</h2>
        </div>
      </div>
      <Table className="authority-table">
        <TableCaption className="sr-only">
          Tenant role definitions and lifecycle state
        </TableCaption>
        <TableHeader>
          {table.getHeaderGroups().map((headerGroup) => (
            <TableRow key={headerGroup.id}>
              {headerGroup.headers.map((header) => (
                <TableHead key={header.id}>
                  {header.isPlaceholder ? null : (
                    <table.FlexRender header={header} />
                  )}
                </TableHead>
              ))}
            </TableRow>
          ))}
        </TableHeader>
        <TableBody>
          {table.getRowModel().rows.map((row) => (
            <TableRow key={row.id}>
              {row.getAllCells().map((cell) => (
                <TableCell key={cell.id}>
                  <table.FlexRender cell={cell} />
                </TableCell>
              ))}
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
          {isLoadingMore ? "Loading roles…" : "Load more roles"}
        </Button>
      ) : null}
    </section>
  );
}

function RoleReadonlyDetails({
  model,
}: {
  model: React.ComponentProps<typeof RoleDetailDialogView>["model"];
}): React.ReactNode {
  const {
    archiveConfirmation,
    archiveError,
    archiveRole,
    canManage,
    editing,
    isArchiving,
    permissions,
    role,
    setArchiveConfirmation,
    setEditing,
  } = model;
  if (!role || editing) return null;
  const canChangeRole =
    canManage &&
    !role.system &&
    role.principalKind === "human" &&
    !role.archived;
  return (
    <>
      {archiveError ? (
        <FocusedError title="Archive failed" message={archiveError} />
      ) : null}
      <RoleMetadata role={role} />
      {role.description ? <p>{role.description}</p> : null}
      <RolePolicySummary policy={role.policy} />
      {archiveConfirmation ? (
        <div className="destructive-confirmation" role="alert">
          <p>
            Archive this custom role? Existing protected recovery invariants may
            still cause the server to reject the action.
          </p>
          <div>
            <Button
              type="button"
              variant="destructive"
              disabled={isArchiving}
              onClick={() => void archiveRole()}
            >
              <Archive aria-hidden="true" />
              {isArchiving ? "Archiving…" : "Confirm archive"}
            </Button>
            <Button
              type="button"
              variant="ghost"
              disabled={isArchiving}
              onClick={() => setArchiveConfirmation(false)}
            >
              Keep role
            </Button>
          </div>
        </div>
      ) : null}
      <DialogFooter>
        {canChangeRole && permissions.length > 0 ? (
          <Button type="button" onClick={() => setEditing(true)}>
            Edit role
          </Button>
        ) : null}
        {canChangeRole && !archiveConfirmation ? (
          <Button
            type="button"
            variant="outline"
            onClick={() => setArchiveConfirmation(true)}
          >
            <Archive aria-hidden="true" /> Archive
          </Button>
        ) : null}
      </DialogFooter>
    </>
  );
}

function RoleCreateAction({
  model,
}: {
  model: React.ComponentProps<typeof RoleWorkspace>["model"];
}): React.ReactNode {
  const {
    activeCreateSelection,
    api,
    authority,
    authorityReadyRef,
    closeCreateRole,
    createGenerationRef,
    createOpen,
    openCreateRole,
    permissionState,
    replaceSummary,
    requestPair,
    requestPairRef,
    session,
    tenantId,
  } = model;
  return tenantId && permissionState.kind === "ready" ? (
    <CreateRoleDialog
      api={api}
      csrfToken={session.csrfToken}
      delegation={authority.authority?.delegationCeiling ?? []}
      onAuthorityChanged={() => {
        if (
          requestPairRef.current === requestPair &&
          authorityReadyRef.current &&
          activeCreateSelection !== null &&
          createGenerationRef.current === activeCreateSelection.generation
        ) {
          authority.reload();
        }
      }}
      onCreated={(role) => {
        if (
          requestPairRef.current !== requestPair ||
          !authorityReadyRef.current ||
          activeCreateSelection === null ||
          createGenerationRef.current !== activeCreateSelection.generation
        ) {
          return;
        }
        replaceSummary(role);
        if (
          activeCreateSelection !== null &&
          createGenerationRef.current === activeCreateSelection.generation
        ) {
          closeCreateRole();
        }
      }}
      onOpenChange={(open) => {
        if (open) {
          openCreateRole();
        } else {
          closeCreateRole();
        }
      }}
      open={createOpen}
      permissions={permissionState.items}
      key={activeCreateSelection?.generation ?? "closed"}
      tenantId={tenantId}
    />
  ) : null;
}

function RoleDetailAction({
  model,
}: {
  model: React.ComponentProps<typeof RoleWorkspace>["model"];
}): React.ReactNode {
  const {
    api,
    authority,
    authorityReadyRef,
    canManage,
    closeRole,
    detailGenerationRef,
    detailState,
    permissionState,
    replaceSummary,
    requestPair,
    requestPairRef,
    selectedRole,
    selectedRoleId,
    session,
    setLoadAttempt,
    tenantId,
  } = model;
  return tenantId && selectedRoleId && selectedRole ? (
    <RoleDetailDialog
      api={api}
      canManage={canManage}
      csrfToken={session.csrfToken}
      delegation={authority.authority?.delegationCeiling ?? []}
      detailState={detailState}
      onChanged={(role) => {
        if (requestPairRef.current !== requestPair) {
          return;
        }
        if (!authorityReadyRef.current) {
          return;
        }
        if (detailGenerationRef.current === selectedRole.generation) {
          replaceSummary(role);
        } else {
          setLoadAttempt((attempt) => attempt + 1);
        }
      }}
      onArchived={() => {
        if (
          requestPairRef.current !== requestPair ||
          !authorityReadyRef.current
        ) {
          return;
        }
        if (detailGenerationRef.current === selectedRole.generation) {
          closeRole();
        }
        setLoadAttempt((attempt) => attempt + 1);
      }}
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
          closeRole();
        }
      }}
      permissions={
        permissionState.kind === "ready" ? permissionState.items : []
      }
      key={`${requestPair}:${selectedRoleId}:${selectedRole.generation}`}
      tenantId={tenantId}
    />
  ) : null;
}

interface RoleMetadataProps {
  role: TenantRoleView;
}

function RoleMetadata({ role }: RoleMetadataProps): React.JSX.Element {
  return (
    <dl className="role-detail-grid">
      <div>
        <dt>Key</dt>
        <dd>{role.key}</dd>
      </div>
      <div>
        <dt>Origin</dt>
        <dd>{role.system ? "Protected built-in" : "Custom"}</dd>
      </div>
      <div>
        <dt>Principal</dt>
        <dd>
          {role.principalKind === "service_account"
            ? "Service account"
            : "Human"}
        </dd>
      </div>
      <div>
        <dt>State</dt>
        <dd>{role.archived ? "Archived" : "Active"}</dd>
      </div>
      <div>
        <dt>Version</dt>
        <dd>v{role.version}</dd>
      </div>
    </dl>
  );
}
