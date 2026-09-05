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
  TableHead,
  TableHeader,
  TableRow,
} from "@periapsis/ui/components/ui/table";
import { Textarea } from "@periapsis/ui/components/ui/textarea";
import { Archive, ArrowDown, Bot, Eye, Plus, RefreshCw } from "lucide-react";
import { useCallback, useEffect, useId, useRef, useState } from "react";

import { useSession } from "../auth/session-context";
import { useTenantAuthority } from "../auth/tenant-authority-context";
import { FocusedError } from "../components/focused-error";
import { FormField } from "../components/form-field";
import { ServerDenied } from "../components/server-denied";
import {
  describePhaseTwoError,
  PhaseTwoApiError,
  tenantProjectionMismatchCode,
  type PhaseTwoApi,
  type ServiceAccountCredentialView,
  type ServiceAccountRoleGrantView,
  type ServiceAccountView,
  type VersionedView,
} from "../lib/phase-two-types";
import {
  assertAccountTenant,
  capitalize,
  deriveInitialListState,
  formatTimestamp,
  isAbortError,
  machineRoleItems,
  mergeCredentials,
  mergeGrants,
  mergeRoles,
  mergeServiceAccounts,
  mutationMessage,
  optionalFutureInstant,
  validateAccountForm,
  validateReason,
  type AccountListState,
  type MachineRoleState,
  type OneTimeSecretState,
  type PaginationState,
  type PairSnapshot,
  type ServiceAccountDetailReady,
  type ServiceAccountDetailState,
} from "./service-account-model";
import {
  RoleAuthorityPanel,
  ServiceAccountAuthorityRail,
} from "./service-account-authority";
import {
  CredentialMutationDialog,
  CredentialPanel,
  OneTimeCredentialDialog,
} from "./service-account-credentials";

export { mergeServiceAccounts } from "./service-account-model";

type LiveReadDenial = "forbidden" | "unauthenticated";

type HandleLiveReadDenial = (
  caught: unknown,
  expectedPair: string,
  expectedSessionId: string,
) => LiveReadDenial | undefined;

type HandleLiveMutationDenial = (
  caught: unknown,
  expectedPair: string,
  expectedSessionId: string,
) => boolean;

export function TenantServiceAccountsPage(): React.JSX.Element {
  const { api, clearSession, session } = useSession();
  const authority = useTenantAuthority();
  const reloadAuthority = authority.reload;
  const tenantId = session.activeTenantId;
  const pairKey = JSON.stringify([session.id, tenantId ?? null]);
  const pairKeyRef = useRef(pairKey);
  pairKeyRef.current = pairKey;
  const canRead = authority.hasPermission("service_account.read", "tenant");
  const canManage = authority.hasPermission("service_account.manage", "tenant");
  const canManageCredentials = authority.hasPermission(
    "service_account.credential.manage",
    "tenant",
  );
  const canGrantRoles =
    canManage && authority.hasPermission("role.grant", "tenant");
  const [readDeniedPair, setReadDeniedPair] = useState<string | null>(null);
  const readDenied = readDeniedPair === pairKey;
  const authorityReady =
    Boolean(tenantId) && authority.status === "ready" && canRead && !readDenied;
  const authorityReadyRef = useRef(authorityReady);
  authorityReadyRef.current = authorityReady;
  const initialState = deriveInitialListState(
    tenantId,
    authority.status,
    authority.message,
    canRead,
  );
  const failClosedInitialState: AccountListState = readDenied
    ? { kind: "forbidden" }
    : initialState;
  const [listSnapshot, setListSnapshot] = useState<
    PairSnapshot<AccountListState>
  >(() => ({ pairKey, state: failClosedInitialState }));
  const listState =
    authorityReady && listSnapshot.pairKey === pairKey
      ? listSnapshot.state
      : failClosedInitialState;
  const [reloadRevision, setReloadRevision] = useState(0);
  const [paginationSnapshot, setPaginationSnapshot] = useState<
    PairSnapshot<PaginationState>
  >(() => ({ pairKey, state: { loading: false } }));
  const pagination =
    paginationSnapshot.pairKey === pairKey
      ? paginationSnapshot.state
      : { loading: false };
  const paginationHistoryRef = useRef(new Set<string>());
  const paginationControllerRef = useRef<AbortController | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [selectedAccountId, setSelectedAccountId] = useState<string | null>(
    null,
  );
  const [notice, setNotice] = useState<string | null>(null);

  const handleLiveReadDenial = useCallback<HandleLiveReadDenial>(
    (caught, expectedPair, expectedSessionId) => {
      if (
        pairKeyRef.current !== expectedPair ||
        !(caught instanceof PhaseTwoApiError)
      ) {
        return undefined;
      }
      if (caught.status === 401) {
        clearSession(expectedSessionId);
        return "unauthenticated";
      }
      if (
        caught.status === 403 ||
        caught.code === tenantProjectionMismatchCode
      ) {
        setReadDeniedPair(expectedPair);
        reloadAuthority();
        return "forbidden";
      }
      return undefined;
    },
    [clearSession, reloadAuthority],
  );

  const handleLiveMutationDenial = useCallback<HandleLiveMutationDenial>(
    (caught, expectedPair, expectedSessionId) => {
      if (
        pairKeyRef.current !== expectedPair ||
        !(caught instanceof PhaseTwoApiError)
      ) {
        return false;
      }
      if (caught.status === 401) {
        clearSession(expectedSessionId);
        return true;
      }
      if (
        caught.status === 403 ||
        caught.code === tenantProjectionMismatchCode
      ) {
        reloadAuthority();
        return true;
      }
      return false;
    },
    [clearSession, reloadAuthority],
  );

  useEffect(() => {
    if (authorityReady) return;
    paginationControllerRef.current?.abort();
    paginationControllerRef.current = null;
    paginationHistoryRef.current.clear();
    setCreateOpen(false);
    setSelectedAccountId(null);
    setNotice(null);
    setPaginationSnapshot({ pairKey, state: { loading: false } });
    setListSnapshot({
      pairKey,
      state: readDenied ? { kind: "forbidden" } : initialState,
    });
  }, [
    authority.message,
    authority.status,
    authorityReady,
    canRead,
    pairKey,
    readDenied,
    tenantId,
  ]);

  useEffect(() => {
    paginationControllerRef.current?.abort();
    paginationControllerRef.current = null;
    paginationHistoryRef.current.clear();
    setPaginationSnapshot({ pairKey, state: { loading: false } });
    if (!tenantId || authority.status !== "ready" || !canRead || readDenied) {
      setListSnapshot({
        pairKey,
        state: readDenied ? { kind: "forbidden" } : initialState,
      });
      return undefined;
    }
    const controller = new AbortController();
    const expectedSessionId = session.id;
    setListSnapshot({ pairKey, state: { kind: "loading" } });
    void api
      .listTenantServiceAccounts(tenantId, {
        includeArchived: true,
        signal: controller.signal,
      })
      .then((page) => {
        if (
          controller.signal.aborted ||
          pairKeyRef.current !== pairKey ||
          !authorityReadyRef.current
        ) {
          return;
        }
        assertAccountTenant(page.items, tenantId);
        if (page.nextCursor) paginationHistoryRef.current.add(page.nextCursor);
        setListSnapshot({
          pairKey,
          state: {
            items: mergeServiceAccounts([], page.items),
            kind: "ready",
            ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
          },
        });
      })
      .catch((caught: unknown) => {
        if (
          controller.signal.aborted ||
          pairKeyRef.current !== pairKey ||
          !authorityReadyRef.current ||
          isAbortError(caught)
        ) {
          return;
        }
        const denial = handleLiveReadDenial(caught, pairKey, expectedSessionId);
        if (denial) {
          if (denial === "forbidden") {
            setListSnapshot({ pairKey, state: { kind: "forbidden" } });
          }
          return;
        }
        setListSnapshot({
          pairKey,
          state: {
            kind: "error",
            message: describePhaseTwoError(
              caught,
              "The service-account inventory could not be loaded.",
            ),
          },
        });
      });
    return () => controller.abort();
  }, [
    api,
    authority.message,
    authority.status,
    canRead,
    handleLiveReadDenial,
    pairKey,
    readDenied,
    reloadRevision,
    session.id,
    tenantId,
  ]);

  useEffect(() => {
    setCreateOpen(false);
    setSelectedAccountId(null);
    setNotice(null);
    return () => {
      paginationControllerRef.current?.abort();
      paginationControllerRef.current = null;
    };
  }, [pairKey]);

  async function loadMoreAccounts(): Promise<void> {
    if (
      !tenantId ||
      !authorityReadyRef.current ||
      listState.kind !== "ready" ||
      !listState.nextCursor ||
      pagination.loading
    ) {
      return;
    }
    const cursor = listState.nextCursor;
    const expectedPair = pairKey;
    const expectedSessionId = session.id;
    paginationControllerRef.current?.abort();
    const controller = new AbortController();
    paginationControllerRef.current = controller;
    setPaginationSnapshot({ pairKey: expectedPair, state: { loading: true } });
    try {
      const page = await api.listTenantServiceAccounts(tenantId, {
        after: cursor,
        includeArchived: true,
        signal: controller.signal,
      });
      if (
        controller.signal.aborted ||
        pairKeyRef.current !== expectedPair ||
        !authorityReadyRef.current
      ) {
        return;
      }
      assertAccountTenant(page.items, tenantId);
      if (
        page.nextCursor &&
        (page.nextCursor === cursor ||
          paginationHistoryRef.current.has(page.nextCursor))
      ) {
        throw new Error("The service-account cursor entered a cycle.");
      }
      if (page.nextCursor) paginationHistoryRef.current.add(page.nextCursor);
      setListSnapshot((current) => {
        if (
          current.pairKey !== expectedPair ||
          current.state.kind !== "ready" ||
          current.state.nextCursor !== cursor
        ) {
          return current;
        }
        try {
          return {
            pairKey: expectedPair,
            state: {
              items: mergeServiceAccounts(current.state.items, page.items),
              kind: "ready",
              ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
            },
          };
        } catch (caught) {
          return {
            pairKey: expectedPair,
            state: {
              kind: "error",
              message: describePhaseTwoError(
                caught,
                "The service-account pages could not be reconciled.",
              ),
            },
          };
        }
      });
    } catch (caught) {
      if (
        controller.signal.aborted ||
        pairKeyRef.current !== expectedPair ||
        !authorityReadyRef.current ||
        isAbortError(caught)
      ) {
        return;
      }
      const denial = handleLiveReadDenial(
        caught,
        expectedPair,
        expectedSessionId,
      );
      if (denial) {
        if (denial === "forbidden") {
          setListSnapshot({
            pairKey: expectedPair,
            state: { kind: "forbidden" },
          });
        }
        return;
      }
      setPaginationSnapshot({
        pairKey: expectedPair,
        state: {
          error: describePhaseTwoError(
            caught,
            "More service accounts could not be loaded.",
          ),
          loading: false,
        },
      });
    } finally {
      if (paginationControllerRef.current === controller) {
        paginationControllerRef.current = null;
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

  const mergeAccount = useCallback(
    (account: ServiceAccountView): void => {
      if (!authorityReadyRef.current || account.tenantId !== tenantId) return;
      setListSnapshot((current) => {
        if (current.pairKey !== pairKey || current.state.kind !== "ready") {
          return current;
        }
        try {
          return {
            pairKey,
            state: {
              ...current.state,
              items: mergeServiceAccounts(current.state.items, [account]),
            },
          };
        } catch (caught) {
          return {
            pairKey,
            state: {
              kind: "error",
              message: describePhaseTwoError(
                caught,
                "The service-account representation could not be reconciled.",
              ),
            },
          };
        }
      });
    },
    [pairKey, tenantId],
  );

  if (listState.kind === "forbidden") {
    return <ServerDenied resource="the tenant service-account inventory" />;
  }
  if (listState.kind === "inactive") {
    return (
      <div className="content content--narrow">
        <section className="page-heading">
          <div>
            <p className="section-label">Machine identities</p>
            <h1>Select a tenant to inspect service accounts.</h1>
            <p>Machine authority is always anchored to one explicit tenant.</p>
          </div>
        </section>
      </div>
    );
  }

  return (
    <div className="content tenant-admin-page service-account-page">
      <section
        className="page-heading service-account-page-heading"
        aria-labelledby="service-accounts-page-title"
      >
        <div>
          <p className="section-label">Machine access / Phase 2B</p>
          <h1 id="service-accounts-page-title">Service accounts</h1>
          <p>
            Keep automation identities, machine-only roles, and redacted API
            credentials in one tenant-bound control surface. Secrets appear once
            and never enter inventory state.
          </p>
        </div>
        <Badge variant="outline">
          <Bot aria-hidden="true" /> Machine principals
        </Badge>
      </section>

      {notice ? (
        <p className="service-account-notice" role="status">
          {notice}
        </p>
      ) : null}
      {pagination.error ? (
        <FocusedError
          title="More service accounts could not be loaded"
          message={pagination.error}
        />
      ) : null}
      {listState.kind === "authority_error" ? (
        <FocusedError
          title="Live authority unavailable"
          message={listState.message}
        />
      ) : null}
      {listState.kind === "loading" ? <ServiceAccountListSkeleton /> : null}
      {listState.kind === "error" ? (
        <div className="tenant-admin-error">
          <FocusedError message={listState.message} />
          <Button
            type="button"
            variant="outline"
            onClick={() => setReloadRevision((revision) => revision + 1)}
          >
            <RefreshCw aria-hidden="true" /> Retry service accounts
          </Button>
        </div>
      ) : null}
      {listState.kind === "ready" ? (
        <section
          className="service-account-inventory"
          aria-labelledby="service-account-inventory-title"
        >
          <div className="section-heading service-account-section-heading">
            <div>
              <p className="section-label">Server inventory</p>
              <h2 id="service-account-inventory-title">
                Automation identities
              </h2>
            </div>
            {canManage ? (
              <Button type="button" onClick={() => setCreateOpen(true)}>
                <Plus aria-hidden="true" /> Create service account
              </Button>
            ) : null}
          </div>
          {listState.items.length === 0 ? (
            <div className="tenant-empty service-account-empty">
              <Bot aria-hidden="true" />
              <h2>No service accounts returned</h2>
              <p>
                {canManage
                  ? "Create a machine identity, then grant exact authority before issuing a credential."
                  : "The server returned no machine identities for this tenant."}
              </p>
            </div>
          ) : (
            <Card className="service-account-table-card">
              <CardContent>
                <Table className="service-account-table">
                  <TableCaption className="sr-only">
                    Service accounts in the active tenant
                  </TableCaption>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Identity</TableHead>
                      <TableHead>State</TableHead>
                      <TableHead>Updated</TableHead>
                      <TableHead>Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {listState.items.map((account) => (
                      <TableRow key={account.id}>
                        <TableCell>
                          <span className="service-account-name-cell">
                            <strong>{account.displayName}</strong>
                            <small>{account.key}</small>
                          </span>
                        </TableCell>
                        <TableCell>
                          <Badge
                            variant={
                              account.state === "active"
                                ? "secondary"
                                : "outline"
                            }
                          >
                            {capitalize(account.state)}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          {formatTimestamp(account.updatedAt)}
                        </TableCell>
                        <TableCell>
                          <Button
                            type="button"
                            size="sm"
                            variant="ghost"
                            aria-label={`Open ${account.displayName} (${account.key})`}
                            onClick={() => setSelectedAccountId(account.id)}
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
          )}
          {listState.nextCursor ? (
            <Button
              type="button"
              variant="outline"
              disabled={pagination.loading}
              onClick={() => void loadMoreAccounts()}
            >
              <ArrowDown aria-hidden="true" />
              {pagination.loading
                ? "Loading service accounts…"
                : "Load more service accounts"}
            </Button>
          ) : null}
        </section>
      ) : null}

      {tenantId && authorityReady && canManage && createOpen ? (
        <CreateServiceAccountDialog
          api={api}
          csrfToken={session.csrfToken}
          pairKey={pairKey}
          onCreated={(account) => {
            if (pairKeyRef.current !== pairKey || !authorityReadyRef.current) {
              return;
            }
            mergeAccount(account.value);
            setNotice("Service account created without implicit authority.");
            setCreateOpen(false);
          }}
          onMutationDenied={handleLiveMutationDenial}
          onOpenChange={setCreateOpen}
          tenantId={tenantId}
        />
      ) : null}

      {tenantId && authorityReady && selectedAccountId ? (
        <ServiceAccountDetailDialog
          accountId={selectedAccountId}
          api={api}
          canGrantRoles={canGrantRoles}
          canManage={canManage}
          canManageCredentials={canManageCredentials}
          csrfToken={session.csrfToken}
          key={`${pairKey}:${selectedAccountId}`}
          onAccountChanged={(account) => mergeAccount(account.value)}
          onArchived={() => {
            if (!authorityReadyRef.current || pairKeyRef.current !== pairKey) {
              return;
            }
            setSelectedAccountId(null);
            setNotice(
              "Service account archived; machine authority is withdrawn.",
            );
            setReloadRevision((revision) => revision + 1);
          }}
          onOpenChange={(open) => {
            if (!open) setSelectedAccountId(null);
          }}
          onMutationDenied={handleLiveMutationDenial}
          onReadDenied={handleLiveReadDenial}
          pairKey={pairKey}
          tenantId={tenantId}
        />
      ) : null}
    </div>
  );
}

function CreateServiceAccountDialog({
  api,
  csrfToken,
  onCreated,
  onMutationDenied,
  onOpenChange,
  pairKey,
  tenantId,
}: {
  api: PhaseTwoApi;
  csrfToken: string;
  onCreated: (account: VersionedView<ServiceAccountView>) => void;
  onMutationDenied: HandleLiveMutationDenial;
  onOpenChange: (open: boolean) => void;
  pairKey: string;
  tenantId: string;
}): React.JSX.Element {
  const { session } = useSession();
  const id = useId();
  const [key, setKey] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [description, setDescription] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const mountedRef = useRef(true);
  const sessionIdRef = useRef(session.id);
  sessionIdRef.current = session.id;

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  async function submit(
    event: React.FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault();
    const validation = validateAccountForm(key, displayName, description);
    if (validation) {
      setError(validation);
      return;
    }
    const expectedSessionId = session.id;
    setSaving(true);
    setError(null);
    try {
      const created = await api.createTenantServiceAccount(
        csrfToken,
        tenantId,
        {
          ...(description.trim() ? { description: description.trim() } : {}),
          displayName: displayName.trim(),
          key: key.trim(),
        },
      );
      if (!mountedRef.current || sessionIdRef.current !== expectedSessionId) {
        return;
      }
      onCreated(created);
    } catch (caught) {
      if (!mountedRef.current || sessionIdRef.current !== expectedSessionId) {
        return;
      }
      if (onMutationDenied(caught, pairKey, expectedSessionId)) return;
      setError(
        mutationMessage(
          caught,
          "The service account was not created. Your input is preserved.",
        ),
      );
    } finally {
      if (mountedRef.current && sessionIdRef.current === expectedSessionId) {
        setSaving(false);
      }
    }
  }

  return (
    <Dialog open onOpenChange={onOpenChange}>
      <DialogContent
        className="service-account-create-dialog"
        data-authority-pair={pairKey}
      >
        <DialogHeader>
          <DialogTitle>Create service account</DialogTitle>
          <DialogDescription>
            Creates a tenant-owned machine identity with no role or credential.
            Authority is granted deliberately after creation.
          </DialogDescription>
        </DialogHeader>
        <form className="service-account-form" onSubmit={submit} noValidate>
          {error ? (
            <FocusedError title="Service account not created" message={error} />
          ) : null}
          <FormField htmlFor={`${id}-account-key`} label="Service account key">
            <Input
              id={`${id}-account-key`}
              autoComplete="off"
              maxLength={64}
              disabled={saving}
              value={key}
              onChange={(event) => setKey(event.target.value)}
            />
          </FormField>
          <FormField htmlFor={`${id}-account-name`} label="Display name">
            <Input
              id={`${id}-account-name`}
              autoComplete="off"
              maxLength={120}
              disabled={saving}
              value={displayName}
              onChange={(event) => setDisplayName(event.target.value)}
            />
          </FormField>
          <FormField
            htmlFor={`${id}-account-description`}
            label="Description"
            optional
          >
            <Textarea
              id={`${id}-account-description`}
              maxLength={500}
              disabled={saving}
              value={description}
              onChange={(event) => setDescription(event.target.value)}
            />
          </FormField>
          <DialogFooter>
            <Button
              type="button"
              variant="ghost"
              disabled={saving}
              onClick={() => onOpenChange(false)}
            >
              Cancel
            </Button>
            <Button type="submit" disabled={saving}>
              {saving ? "Creating account…" : "Create service account"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function ServiceAccountDetailDialog({
  accountId,
  api,
  canGrantRoles,
  canManage,
  canManageCredentials,
  csrfToken,
  onAccountChanged,
  onArchived,
  onMutationDenied,
  onOpenChange,
  onReadDenied,
  pairKey,
  tenantId,
}: {
  accountId: string;
  api: PhaseTwoApi;
  canGrantRoles: boolean;
  canManage: boolean;
  canManageCredentials: boolean;
  csrfToken: string;
  onAccountChanged: (account: VersionedView<ServiceAccountView>) => void;
  onArchived: () => void;
  onMutationDenied: HandleLiveMutationDenial;
  onOpenChange: (open: boolean) => void;
  onReadDenied: HandleLiveReadDenial;
  pairKey: string;
  tenantId: string;
}): React.JSX.Element {
  const { session } = useSession();
  const id = useId();
  const pairKeyRef = useRef(pairKey);
  pairKeyRef.current = pairKey;
  const mountedRef = useRef(true);
  const sessionIdRef = useRef(session.id);
  sessionIdRef.current = session.id;
  const canManageRef = useRef(canManage);
  canManageRef.current = canManage;
  const canGrantRolesRef = useRef(canGrantRoles);
  canGrantRolesRef.current = canGrantRoles;
  const canManageCredentialsRef = useRef(canManageCredentials);
  canManageCredentialsRef.current = canManageCredentials;
  const requestGenerationRef = useRef(0);
  const [reloadRevision, setReloadRevision] = useState(0);
  const [detail, setDetail] = useState<ServiceAccountDetailState>({
    kind: "loading",
  });
  const [activeTab, setActiveTab] = useState<
    "credentials" | "overview" | "roles"
  >("overview");
  const [machineRoles, setMachineRoles] = useState<MachineRoleState>({
    kind: canGrantRoles ? "loading" : "inactive",
  });
  const roleCursorHistoryRef = useRef(new Set<string>());
  const grantCursorHistoryRef = useRef(new Set<string>());
  const credentialCursorHistoryRef = useRef(new Set<string>());
  const [grantPagination, setGrantPagination] = useState<PaginationState>({
    loading: false,
  });
  const [credentialPagination, setCredentialPagination] =
    useState<PaginationState>({ loading: false });
  const [rolePagination, setRolePagination] = useState<PaginationState>({
    loading: false,
  });
  const [displayName, setDisplayName] = useState("");
  const [description, setDescription] = useState("");
  const metadataInitializedRef = useRef(false);
  const [metadataError, setMetadataError] = useState<string | null>(null);
  const [metadataSaving, setMetadataSaving] = useState(false);
  const [archiveReason, setArchiveReason] = useState("");
  const [archiveError, setArchiveError] = useState<string | null>(null);
  const [archiving, setArchiving] = useState(false);
  const [grantRoleId, setGrantRoleId] = useState("");
  const [grantReason, setGrantReason] = useState("");
  const [grantExpiresAt, setGrantExpiresAt] = useState("");
  const [grantError, setGrantError] = useState<string | null>(null);
  const [grantSaving, setGrantSaving] = useState(false);
  const [grantRevokeReasons, setGrantRevokeReasons] = useState<
    Readonly<Record<string, string>>
  >({});
  const [grantRevokingId, setGrantRevokingId] = useState<string | null>(null);
  const [issueOpen, setIssueOpen] = useState(false);
  const [rotateCredential, setRotateCredential] =
    useState<ServiceAccountCredentialView | null>(null);
  const [oneTimeSecret, setOneTimeSecret] = useState<OneTimeSecretState | null>(
    null,
  );
  const [selectedCredentialId, setSelectedCredentialId] = useState<
    string | null
  >(null);
  const selectedCredentialIdRef = useRef<string | null>(null);
  selectedCredentialIdRef.current = selectedCredentialId;
  const [credentialDetail, setCredentialDetail] = useState<
    | { kind: "error"; message: string }
    | { kind: "loading" }
    | { credential: VersionedView<ServiceAccountCredentialView>; kind: "ready" }
    | null
  >(null);
  const credentialDetailControllerRef = useRef<AbortController | null>(null);
  const [credentialActionError, setCredentialActionError] = useState<
    string | null
  >(null);
  const [credentialRevokeReason, setCredentialRevokeReason] = useState("");
  const [credentialRevoking, setCredentialRevoking] = useState(false);

  const isCurrent = useCallback(
    (expectedPair: string, expectedSessionId: string): boolean =>
      mountedRef.current &&
      pairKeyRef.current === expectedPair &&
      sessionIdRef.current === expectedSessionId,
    [],
  );

  const reloadDetail = useCallback(() => {
    setReloadRevision((revision) => revision + 1);
  }, []);

  useEffect(() => {
    const generation = requestGenerationRef.current + 1;
    requestGenerationRef.current = generation;
    const controller = new AbortController();
    const expectedSessionId = session.id;
    setDetail({ kind: "loading" });
    setGrantPagination({ loading: false });
    setCredentialPagination({ loading: false });
    grantCursorHistoryRef.current.clear();
    credentialCursorHistoryRef.current.clear();
    void Promise.all([
      api.getTenantServiceAccount(tenantId, accountId, controller.signal),
      api.listTenantServiceAccountRoleGrants(tenantId, accountId, {
        includeRevoked: true,
        signal: controller.signal,
      }),
      api.listTenantServiceAccountCredentials(tenantId, accountId, {
        includeRevoked: true,
        signal: controller.signal,
      }),
    ])
      .then(([account, grants, credentials]) => {
        if (
          controller.signal.aborted ||
          pairKeyRef.current !== pairKey ||
          requestGenerationRef.current !== generation
        ) {
          return;
        }
        if (grants.nextCursor) {
          grantCursorHistoryRef.current.add(grants.nextCursor);
        }
        if (credentials.nextCursor) {
          credentialCursorHistoryRef.current.add(credentials.nextCursor);
        }
        setDetail({ account, credentials, grants, kind: "ready" });
        if (!metadataInitializedRef.current) {
          metadataInitializedRef.current = true;
          setDisplayName(account.value.displayName);
          setDescription(account.value.description);
        }
      })
      .catch((caught: unknown) => {
        if (
          controller.signal.aborted ||
          pairKeyRef.current !== pairKey ||
          requestGenerationRef.current !== generation ||
          isAbortError(caught)
        ) {
          return;
        }
        const denial = onReadDenied(caught, pairKey, expectedSessionId);
        if (denial) {
          if (denial === "forbidden") setDetail({ kind: "forbidden" });
          return;
        }
        setDetail({
          kind: "error",
          message: describePhaseTwoError(
            caught,
            "The service-account detail could not be loaded.",
          ),
        });
      });
    return () => controller.abort();
  }, [
    accountId,
    api,
    onReadDenied,
    pairKey,
    reloadRevision,
    session.id,
    tenantId,
  ]);

  useEffect(() => {
    roleCursorHistoryRef.current.clear();
    setRolePagination({ loading: false });
    if (!canGrantRoles) {
      setMachineRoles({ kind: "inactive" });
      return undefined;
    }
    const controller = new AbortController();
    const expectedSessionId = session.id;
    setMachineRoles({ kind: "loading" });
    void api
      .listTenantRoles(tenantId, {
        includeArchived: false,
        signal: controller.signal,
      })
      .then((page) => {
        if (
          controller.signal.aborted ||
          pairKeyRef.current !== pairKey ||
          !canGrantRolesRef.current
        ) {
          return;
        }
        if (page.nextCursor) roleCursorHistoryRef.current.add(page.nextCursor);
        setMachineRoles({
          items: machineRoleItems(page),
          kind: "ready",
          ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
        });
      })
      .catch((caught: unknown) => {
        if (
          controller.signal.aborted ||
          pairKeyRef.current !== pairKey ||
          !canGrantRolesRef.current ||
          isAbortError(caught)
        ) {
          return;
        }
        if (onReadDenied(caught, pairKey, expectedSessionId)) return;
        setMachineRoles({
          kind: "error",
          message: describePhaseTwoError(
            caught,
            "Machine-role choices could not be loaded.",
          ),
        });
      });
    return () => controller.abort();
  }, [api, canGrantRoles, onReadDenied, pairKey, session.id, tenantId]);

  useEffect(() => {
    if (!canManage) {
      setMetadataError(null);
      setArchiveError(null);
    }
    if (!canGrantRoles) {
      setGrantError(null);
      setGrantRevokingId(null);
    }
    if (!canManageCredentials) {
      setIssueOpen(false);
      setRotateCredential(null);
      setOneTimeSecret(null);
      setCredentialActionError(null);
      setCredentialRevoking(false);
    }
  }, [canGrantRoles, canManage, canManageCredentials]);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      requestGenerationRef.current += 1;
      credentialDetailControllerRef.current?.abort();
      credentialDetailControllerRef.current = null;
    };
  }, []);

  function updateReady(
    update: (current: ServiceAccountDetailReady) => ServiceAccountDetailReady,
  ): void {
    setDetail((current) =>
      current.kind === "ready" ? update(current) : current,
    );
  }

  async function saveMetadata(
    event: React.FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault();
    if (!canManageRef.current || detail.kind !== "ready") return;
    const validation = validateAccountForm(
      detail.account.value.key,
      displayName,
      description,
    );
    if (validation) {
      setMetadataError(validation);
      return;
    }
    const expectedPair = pairKey;
    const expectedSessionId = session.id;
    setMetadataSaving(true);
    setMetadataError(null);
    try {
      const account = await api.updateTenantServiceAccount(
        csrfToken,
        tenantId,
        accountId,
        detail.account.etag,
        {
          description: description.trim(),
          displayName: displayName.trim(),
        },
      );
      if (
        !isCurrent(expectedPair, expectedSessionId) ||
        !canManageRef.current
      ) {
        return;
      }
      updateReady((current) => ({ ...current, account }));
      setDisplayName(account.value.displayName);
      setDescription(account.value.description);
      onAccountChanged(account);
    } catch (caught) {
      if (!isCurrent(expectedPair, expectedSessionId)) return;
      if (onMutationDenied(caught, expectedPair, expectedSessionId)) return;
      if (caught instanceof PhaseTwoApiError && caught.status === 412) {
        setMetadataError(
          "This account changed on the server. The latest ETag is loading; your edits are preserved for review.",
        );
        reloadDetail();
        return;
      }
      setMetadataError(
        mutationMessage(
          caught,
          "The account metadata was not saved. Your edits are preserved.",
        ),
      );
    } finally {
      if (isCurrent(expectedPair, expectedSessionId)) {
        setMetadataSaving(false);
      }
    }
  }

  async function archiveAccount(
    event: React.FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault();
    if (!canManageRef.current || detail.kind !== "ready") return;
    const reasonError = validateReason(archiveReason);
    if (reasonError) {
      setArchiveError(reasonError);
      return;
    }
    const expectedPair = pairKey;
    const expectedSessionId = session.id;
    setArchiving(true);
    setArchiveError(null);
    try {
      await api.archiveTenantServiceAccount(
        csrfToken,
        tenantId,
        accountId,
        detail.account.etag,
        { reason: archiveReason.trim() },
      );
      if (
        !isCurrent(expectedPair, expectedSessionId) ||
        !canManageRef.current
      ) {
        return;
      }
      onArchived();
    } catch (caught) {
      if (!isCurrent(expectedPair, expectedSessionId)) return;
      if (onMutationDenied(caught, expectedPair, expectedSessionId)) return;
      if (caught instanceof PhaseTwoApiError && caught.status === 412) {
        setArchiveError(
          "This account changed before archival. The latest ETag is loading; the reason is preserved.",
        );
        reloadDetail();
        return;
      }
      setArchiveError(
        mutationMessage(caught, "The service account was not archived."),
      );
    } finally {
      if (isCurrent(expectedPair, expectedSessionId)) setArchiving(false);
    }
  }

  return (
    <Dialog open onOpenChange={onOpenChange}>
      <DialogContent className="service-account-detail-dialog">
        <DialogHeader>
          <DialogTitle>Service-account control</DialogTitle>
          <DialogDescription>
            Account metadata, machine-role authority, and redacted credentials
            remain separate lifecycle boundaries.
          </DialogDescription>
        </DialogHeader>
        {detail.kind === "loading" ? <ServiceAccountDetailSkeleton /> : null}
        {detail.kind === "forbidden" ? (
          <ServerDenied resource="this service account" />
        ) : null}
        {detail.kind === "error" ? (
          <div className="service-account-detail-error">
            <FocusedError message={detail.message} />
            <Button type="button" variant="outline" onClick={reloadDetail}>
              <RefreshCw aria-hidden="true" /> Retry account detail
            </Button>
          </div>
        ) : null}
        {detail.kind === "ready" ? (
          <div className="service-account-detail-ready">
            <ServiceAccountAuthorityRail detail={detail} />
            <div className="service-account-tabs" role="tablist">
              <button
                id={`${id}-overview-tab`}
                type="button"
                role="tab"
                aria-controls={`${id}-overview-panel`}
                aria-selected={activeTab === "overview"}
                onClick={() => setActiveTab("overview")}
              >
                Account
              </button>
              <button
                id={`${id}-roles-tab`}
                type="button"
                role="tab"
                aria-controls={`${id}-roles-panel`}
                aria-selected={activeTab === "roles"}
                onClick={() => setActiveTab("roles")}
              >
                Machine roles
              </button>
              <button
                id={`${id}-credentials-tab`}
                type="button"
                role="tab"
                aria-controls={`${id}-credentials-panel`}
                aria-selected={activeTab === "credentials"}
                onClick={() => setActiveTab("credentials")}
              >
                API credentials
              </button>
            </div>

            <section
              id={`${id}-overview-panel`}
              role="tabpanel"
              aria-labelledby={`${id}-overview-tab`}
              hidden={activeTab !== "overview"}
              tabIndex={0}
              className="service-account-tab-panel"
            >
              <dl className="service-account-facts">
                <div>
                  <dt>Immutable key</dt>
                  <dd>
                    <code>{detail.account.value.key}</code>
                  </dd>
                </div>
                <div>
                  <dt>Principal</dt>
                  <dd>Service account</dd>
                </div>
                <div>
                  <dt>State</dt>
                  <dd>{capitalize(detail.account.value.state)}</dd>
                </div>
                <div>
                  <dt>ETag</dt>
                  <dd>
                    <code>{detail.account.etag}</code>
                  </dd>
                </div>
              </dl>
              {canManage && detail.account.value.state === "active" ? (
                <form
                  className="service-account-form service-account-metadata-form"
                  onSubmit={saveMetadata}
                  noValidate
                >
                  <div>
                    <p className="section-label">Mutable metadata</p>
                    <h3>Account identity</h3>
                  </div>
                  {metadataError ? (
                    <FocusedError
                      title="Account not updated"
                      message={metadataError}
                    />
                  ) : null}
                  <FormField htmlFor={`${id}-detail-name`} label="Display name">
                    <Input
                      id={`${id}-detail-name`}
                      maxLength={120}
                      disabled={metadataSaving}
                      value={displayName}
                      onChange={(event) => setDisplayName(event.target.value)}
                    />
                  </FormField>
                  <FormField
                    htmlFor={`${id}-detail-description`}
                    label="Description"
                    optional
                  >
                    <Textarea
                      id={`${id}-detail-description`}
                      maxLength={500}
                      disabled={metadataSaving}
                      value={description}
                      onChange={(event) => setDescription(event.target.value)}
                    />
                  </FormField>
                  <Button type="submit" disabled={metadataSaving}>
                    {metadataSaving ? "Saving account…" : "Save account"}
                  </Button>
                </form>
              ) : (
                <p className="capability-note">
                  Account metadata is read-only without live
                  service_account.manage@tenant authority.
                </p>
              )}

              {canManage && detail.account.value.state === "active" ? (
                <Card className="service-account-danger-card">
                  <CardHeader>
                    <CardTitle>Archive machine identity</CardTitle>
                    <CardDescription>
                      Archival is permanent and immediately removes every role
                      and credential from live authority.
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <form
                      className="service-account-form"
                      onSubmit={archiveAccount}
                      noValidate
                    >
                      {archiveError ? (
                        <FocusedError
                          title="Account not archived"
                          message={archiveError}
                        />
                      ) : null}
                      <FormField
                        htmlFor={`${id}-archive-reason`}
                        label="Archive reason"
                      >
                        <Textarea
                          id={`${id}-archive-reason`}
                          maxLength={500}
                          disabled={archiving}
                          value={archiveReason}
                          onChange={(event) =>
                            setArchiveReason(event.target.value)
                          }
                        />
                      </FormField>
                      <Button
                        type="submit"
                        variant="destructive"
                        disabled={archiving}
                      >
                        <Archive aria-hidden="true" />
                        {archiving
                          ? "Archiving account…"
                          : "Archive service account"}
                      </Button>
                    </form>
                  </CardContent>
                </Card>
              ) : null}
            </section>

            <RoleAuthorityPanel
              account={detail.account.value}
              canGrantRoles={canGrantRoles}
              grantError={grantError}
              grantExpiresAt={grantExpiresAt}
              grantPagination={grantPagination}
              grantReason={grantReason}
              grantRevokeReasons={grantRevokeReasons}
              grantRevokingId={grantRevokingId}
              grants={detail.grants}
              grantRoleId={grantRoleId}
              grantSaving={grantSaving}
              hidden={activeTab !== "roles"}
              id={id}
              machineRoles={machineRoles}
              onGrantExpiresAtChange={setGrantExpiresAt}
              onGrantReasonChange={setGrantReason}
              onGrantRevokeReasonChange={(grantId, reason) =>
                setGrantRevokeReasons((current) => ({
                  ...current,
                  [grantId]: reason,
                }))
              }
              onGrantRoleIdChange={setGrantRoleId}
              onGrantSubmit={(event) => void grantRole(event)}
              onLoadMoreGrants={() => void loadMoreGrants()}
              onLoadMoreRoles={() => void loadMoreMachineRoles()}
              onRevoke={(grant) => void revokeGrant(grant)}
              rolePagination={rolePagination}
            />

            <CredentialPanel
              account={detail.account.value}
              canManageCredentials={canManageCredentials}
              credentialActionError={credentialActionError}
              credentialDetail={credentialDetail}
              credentialPagination={credentialPagination}
              credentialRevokeReason={credentialRevokeReason}
              credentialRevoking={credentialRevoking}
              credentials={detail.credentials}
              hidden={activeTab !== "credentials"}
              id={id}
              onCloseCredential={() => {
                credentialDetailControllerRef.current?.abort();
                credentialDetailControllerRef.current = null;
                setSelectedCredentialId(null);
                selectedCredentialIdRef.current = null;
                setCredentialDetail(null);
                setCredentialActionError(null);
                setCredentialRevokeReason("");
              }}
              onIssue={() => setIssueOpen(true)}
              onLoadMore={() => void loadMoreCredentials()}
              onOpenCredential={(credential) =>
                void openCredentialDetail(credential.id)
              }
              onRevoke={() => void revokeCredential()}
              onRevokeReasonChange={setCredentialRevokeReason}
              onRotate={(credential) => setRotateCredential(credential)}
              selectedCredentialId={selectedCredentialId}
            />
          </div>
        ) : null}
        <DialogFooter>
          <Button
            type="button"
            variant="outline"
            onClick={() => onOpenChange(false)}
          >
            Close account
          </Button>
        </DialogFooter>
      </DialogContent>

      {detail.kind === "ready" && canManageCredentials && issueOpen ? (
        <CredentialMutationDialog
          accountId={accountId}
          api={api}
          csrfToken={csrfToken}
          mode="issue"
          onMutationDenied={onMutationDenied}
          onOpenChange={setIssueOpen}
          onReadDenied={onReadDenied}
          onReconciled={(credential) => {
            if (pairKeyRef.current !== pairKey) return;
            updateReady((current) => ({
              ...current,
              credentials: {
                ...current.credentials,
                items: mergeCredentials(current.credentials.items, [
                  credential,
                ]),
              },
            }));
          }}
          onSecret={(secret) => {
            if (
              pairKeyRef.current !== pairKey ||
              !canManageCredentialsRef.current
            ) {
              return;
            }
            updateReady((current) => ({
              ...current,
              credentials: {
                ...current.credentials,
                items: mergeCredentials(current.credentials.items, [
                  secret.credential,
                ]),
              },
            }));
            setIssueOpen(false);
            setOneTimeSecret({ operation: "issued", pairKey, secret });
          }}
          pairKey={pairKey}
          tenantId={tenantId}
        />
      ) : null}

      {detail.kind === "ready" && canManageCredentials && rotateCredential ? (
        <CredentialMutationDialog
          accountId={accountId}
          api={api}
          csrfToken={csrfToken}
          credential={rotateCredential}
          mode="rotate"
          onMutationDenied={onMutationDenied}
          onOpenChange={(open) => {
            if (!open) setRotateCredential(null);
          }}
          onReadDenied={onReadDenied}
          onReconciled={(credential) => {
            if (pairKeyRef.current !== pairKey) return;
            setRotateCredential(credential);
            updateReady((current) => ({
              ...current,
              credentials: {
                ...current.credentials,
                items: mergeCredentials(current.credentials.items, [
                  credential,
                ]),
              },
            }));
          }}
          onSecret={(secret) => {
            if (
              pairKeyRef.current !== pairKey ||
              !canManageCredentialsRef.current
            ) {
              return;
            }
            updateReady((current) => ({
              ...current,
              credentials: {
                ...current.credentials,
                items: mergeCredentials(current.credentials.items, [
                  secret.credential,
                ]),
              },
            }));
            setRotateCredential(null);
            setOneTimeSecret({ operation: "rotated", pairKey, secret });
            reloadCredentialInventory();
          }}
          pairKey={pairKey}
          tenantId={tenantId}
        />
      ) : null}

      {canManageCredentials && oneTimeSecret?.pairKey === pairKey ? (
        <OneTimeCredentialDialog
          state={oneTimeSecret}
          onDismiss={() => setOneTimeSecret(null)}
        />
      ) : null}
    </Dialog>
  );

  async function grantRole(
    event: React.FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault();
    if (!canGrantRolesRef.current || detail.kind !== "ready" || !grantRoleId) {
      return;
    }
    const selectedRole =
      machineRoles.kind === "ready"
        ? machineRoles.items.find((role) => role.id === grantRoleId)
        : undefined;
    if (!selectedRole || selectedRole.principalKind !== "service_account") {
      setGrantError("Select a live machine-only role.");
      return;
    }
    const reasonError = validateReason(grantReason);
    if (reasonError) {
      setGrantError(reasonError);
      return;
    }
    const expiresAt = optionalFutureInstant(grantExpiresAt);
    if (grantExpiresAt && !expiresAt) {
      setGrantError("Choose a future role-grant expiry.");
      return;
    }
    const expectedPair = pairKey;
    const expectedSessionId = session.id;
    setGrantSaving(true);
    setGrantError(null);
    try {
      const grant = await api.grantTenantServiceAccountRole(
        csrfToken,
        tenantId,
        accountId,
        {
          ...(expiresAt ? { expiresAt } : {}),
          reason: grantReason.trim(),
          roleId: selectedRole.id,
        },
      );
      if (
        !isCurrent(expectedPair, expectedSessionId) ||
        !canGrantRolesRef.current
      ) {
        return;
      }
      updateReady((current) => ({
        ...current,
        grants: {
          ...current.grants,
          items: mergeGrants(current.grants.items, [grant.value]),
        },
      }));
      setGrantRoleId("");
      setGrantReason("");
      setGrantExpiresAt("");
    } catch (caught) {
      if (!isCurrent(expectedPair, expectedSessionId)) return;
      if (onMutationDenied(caught, expectedPair, expectedSessionId)) return;
      setGrantError(
        mutationMessage(caught, "The machine-role grant was not created."),
      );
    } finally {
      if (isCurrent(expectedPair, expectedSessionId)) setGrantSaving(false);
    }
  }

  async function revokeGrant(
    grant: ServiceAccountRoleGrantView,
  ): Promise<void> {
    if (!canGrantRolesRef.current || grant.state === "revoked") return;
    const reason = grantRevokeReasons[grant.id] ?? "";
    const reasonError = validateReason(reason);
    if (reasonError) {
      setGrantError(reasonError);
      return;
    }
    const expectedPair = pairKey;
    const expectedSessionId = session.id;
    setGrantRevokingId(grant.id);
    setGrantError(null);
    try {
      await api.revokeTenantServiceAccountRoleGrant(
        csrfToken,
        tenantId,
        accountId,
        grant.id,
        grant.etag,
        { reason: reason.trim() },
      );
      if (
        !isCurrent(expectedPair, expectedSessionId) ||
        !canGrantRolesRef.current
      ) {
        return;
      }
      reloadDetail();
    } catch (caught) {
      if (!isCurrent(expectedPair, expectedSessionId)) return;
      if (onMutationDenied(caught, expectedPair, expectedSessionId)) return;
      if (caught instanceof PhaseTwoApiError && caught.status === 412) {
        setGrantError(
          "This grant changed on the server. The latest representation and ETag are loading; the revoke reason is preserved.",
        );
        reloadDetail();
        return;
      }
      setGrantError(
        mutationMessage(caught, "The machine-role grant was not revoked."),
      );
    } finally {
      if (isCurrent(expectedPair, expectedSessionId)) setGrantRevokingId(null);
    }
  }

  async function loadMoreGrants(): Promise<void> {
    if (
      detail.kind !== "ready" ||
      !detail.grants.nextCursor ||
      grantPagination.loading
    ) {
      return;
    }
    const cursor = detail.grants.nextCursor;
    const expectedPair = pairKey;
    const expectedSessionId = session.id;
    setGrantPagination({ loading: true });
    try {
      const page = await api.listTenantServiceAccountRoleGrants(
        tenantId,
        accountId,
        { after: cursor, includeRevoked: true },
      );
      if (pairKeyRef.current !== expectedPair) return;
      if (
        page.nextCursor &&
        (page.nextCursor === cursor ||
          grantCursorHistoryRef.current.has(page.nextCursor))
      ) {
        throw new Error("The machine-role grant cursor entered a cycle.");
      }
      if (page.nextCursor) grantCursorHistoryRef.current.add(page.nextCursor);
      updateReady((current) =>
        current.grants.nextCursor === cursor
          ? {
              ...current,
              grants: {
                items: mergeGrants(current.grants.items, page.items),
                ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
              },
            }
          : current,
      );
    } catch (caught) {
      if (pairKeyRef.current !== expectedPair) return;
      if (onReadDenied(caught, expectedPair, expectedSessionId)) return;
      setGrantPagination({
        error: describePhaseTwoError(
          caught,
          "More machine-role grants could not be loaded.",
        ),
        loading: false,
      });
    } finally {
      if (pairKeyRef.current === expectedPair) {
        setGrantPagination((current) => ({ ...current, loading: false }));
      }
    }
  }

  async function loadMoreMachineRoles(): Promise<void> {
    if (
      !canGrantRolesRef.current ||
      machineRoles.kind !== "ready" ||
      !machineRoles.nextCursor ||
      rolePagination.loading
    ) {
      return;
    }
    const cursor = machineRoles.nextCursor;
    const expectedPair = pairKey;
    const expectedSessionId = session.id;
    setRolePagination({ loading: true });
    try {
      const page = await api.listTenantRoles(tenantId, {
        after: cursor,
        includeArchived: false,
      });
      if (pairKeyRef.current !== expectedPair || !canGrantRolesRef.current) {
        return;
      }
      if (
        page.nextCursor &&
        (page.nextCursor === cursor ||
          roleCursorHistoryRef.current.has(page.nextCursor))
      ) {
        throw new Error("The machine-role catalog cursor entered a cycle.");
      }
      if (page.nextCursor) roleCursorHistoryRef.current.add(page.nextCursor);
      setMachineRoles((current) =>
        current.kind === "ready" && current.nextCursor === cursor
          ? {
              items: mergeRoles(current.items, machineRoleItems(page)),
              kind: "ready",
              ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
            }
          : current,
      );
    } catch (caught) {
      if (pairKeyRef.current !== expectedPair) return;
      if (onReadDenied(caught, expectedPair, expectedSessionId)) return;
      setRolePagination({
        error: describePhaseTwoError(
          caught,
          "More machine roles could not be loaded.",
        ),
        loading: false,
      });
    } finally {
      if (pairKeyRef.current === expectedPair) {
        setRolePagination((current) => ({ ...current, loading: false }));
      }
    }
  }

  async function loadMoreCredentials(): Promise<void> {
    if (
      detail.kind !== "ready" ||
      !detail.credentials.nextCursor ||
      credentialPagination.loading
    ) {
      return;
    }
    const cursor = detail.credentials.nextCursor;
    const expectedPair = pairKey;
    const expectedSessionId = session.id;
    setCredentialPagination({ loading: true });
    try {
      const page = await api.listTenantServiceAccountCredentials(
        tenantId,
        accountId,
        { after: cursor, includeRevoked: true },
      );
      if (pairKeyRef.current !== expectedPair) return;
      if (
        page.nextCursor &&
        (page.nextCursor === cursor ||
          credentialCursorHistoryRef.current.has(page.nextCursor))
      ) {
        throw new Error("The credential cursor entered a cycle.");
      }
      if (page.nextCursor) {
        credentialCursorHistoryRef.current.add(page.nextCursor);
      }
      updateReady((current) =>
        current.credentials.nextCursor === cursor
          ? {
              ...current,
              credentials: {
                items: mergeCredentials(current.credentials.items, page.items),
                ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
              },
            }
          : current,
      );
    } catch (caught) {
      if (pairKeyRef.current !== expectedPair) return;
      if (onReadDenied(caught, expectedPair, expectedSessionId)) return;
      setCredentialPagination({
        error: describePhaseTwoError(
          caught,
          "More redacted credentials could not be loaded.",
        ),
        loading: false,
      });
    } finally {
      if (pairKeyRef.current === expectedPair) {
        setCredentialPagination((current) => ({
          ...current,
          loading: false,
        }));
      }
    }
  }

  function reloadCredentialInventory(): void {
    const expectedPair = pairKey;
    const expectedSessionId = session.id;
    void api
      .listTenantServiceAccountCredentials(tenantId, accountId, {
        includeRevoked: true,
      })
      .then((page) => {
        if (pairKeyRef.current !== expectedPair) return;
        credentialCursorHistoryRef.current.clear();
        if (page.nextCursor) {
          credentialCursorHistoryRef.current.add(page.nextCursor);
        }
        updateReady((current) => ({
          ...current,
          credentials: page,
        }));
      })
      .catch((caught: unknown) => {
        if (onReadDenied(caught, expectedPair, expectedSessionId)) return;
        // The successful mutation remains authoritative. A visible retry stays
        // available through the detail refresh without surfacing secret data.
      });
  }

  async function openCredentialDetail(credentialId: string): Promise<void> {
    credentialDetailControllerRef.current?.abort();
    const controller = new AbortController();
    credentialDetailControllerRef.current = controller;
    const expectedPair = pairKey;
    const expectedSessionId = session.id;
    setSelectedCredentialId(credentialId);
    selectedCredentialIdRef.current = credentialId;
    setCredentialDetail({ kind: "loading" });
    setCredentialActionError(null);
    try {
      const credential = await api.getTenantServiceAccountCredential(
        tenantId,
        accountId,
        credentialId,
        controller.signal,
      );
      if (
        controller.signal.aborted ||
        pairKeyRef.current !== expectedPair ||
        selectedCredentialIdRef.current !== credentialId
      ) {
        return;
      }
      setCredentialDetail({ credential, kind: "ready" });
      updateReady((current) => ({
        ...current,
        credentials: {
          ...current.credentials,
          items: mergeCredentials(current.credentials.items, [
            credential.value,
          ]),
        },
      }));
    } catch (caught) {
      if (
        controller.signal.aborted ||
        pairKeyRef.current !== expectedPair ||
        isAbortError(caught)
      ) {
        return;
      }
      if (onReadDenied(caught, expectedPair, expectedSessionId)) return;
      setCredentialDetail({
        kind: "error",
        message: describePhaseTwoError(
          caught,
          "The redacted credential detail could not be loaded.",
        ),
      });
    } finally {
      if (credentialDetailControllerRef.current === controller) {
        credentialDetailControllerRef.current = null;
      }
    }
  }

  async function revokeCredential(): Promise<void> {
    if (
      !canManageCredentialsRef.current ||
      credentialDetail?.kind !== "ready"
    ) {
      return;
    }
    const reasonError = validateReason(credentialRevokeReason);
    if (reasonError) {
      setCredentialActionError(reasonError);
      return;
    }
    const credential = credentialDetail.credential;
    const expectedPair = pairKey;
    const expectedSessionId = session.id;
    setCredentialRevoking(true);
    setCredentialActionError(null);
    try {
      await api.revokeTenantServiceAccountCredential(
        csrfToken,
        tenantId,
        accountId,
        credential.value.id,
        credential.etag,
        { reason: credentialRevokeReason.trim() },
      );
      if (
        !isCurrent(expectedPair, expectedSessionId) ||
        !canManageCredentialsRef.current
      ) {
        return;
      }
      setSelectedCredentialId(null);
      selectedCredentialIdRef.current = null;
      setCredentialDetail(null);
      setCredentialRevokeReason("");
      reloadCredentialInventory();
    } catch (caught) {
      if (!isCurrent(expectedPair, expectedSessionId)) return;
      if (onMutationDenied(caught, expectedPair, expectedSessionId)) return;
      if (caught instanceof PhaseTwoApiError && caught.status === 412) {
        setCredentialActionError(
          "This credential changed on the server. Its current redacted detail and ETag are loading; the revoke reason is preserved.",
        );
        await openCredentialDetail(credential.value.id);
        return;
      }
      setCredentialActionError(
        mutationMessage(caught, "The credential was not revoked."),
      );
    } finally {
      if (isCurrent(expectedPair, expectedSessionId)) {
        setCredentialRevoking(false);
      }
    }
  }
}

function ServiceAccountListSkeleton(): React.JSX.Element {
  return (
    <div className="tenant-list-skeleton" aria-label="Loading service accounts">
      <span />
      <span />
      <span />
    </div>
  );
}

function ServiceAccountDetailSkeleton(): React.JSX.Element {
  return (
    <div
      className="service-account-detail-skeleton"
      aria-label="Loading service-account detail"
    >
      <span />
      <span />
      <span />
    </div>
  );
}
