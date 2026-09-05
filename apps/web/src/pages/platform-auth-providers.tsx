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
import { Textarea } from "@periapsis/ui/components/ui/textarea";
import {
  Archive,
  CheckCircle2,
  CircleSlash2,
  Fingerprint,
  KeyRound,
  LockKeyhole,
  Network,
  Plus,
  RefreshCw,
  Save,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
} from "lucide-react";
import { useCallback, useEffect, useId, useRef, useState } from "react";

import { useSession } from "../auth/session-context";
import { FocusedError } from "../components/focused-error";
import { FormField } from "../components/form-field";
import { idempotencyKeyForPayload } from "../lib/payload-idempotency";
import {
  describePhaseTwoError,
  hasPermission,
  PhaseTwoApiError,
  platformIdentityAccountManagePermission,
  platformIdentityAccountReadPermission,
  platformIdentityProviderManagePermission,
  platformIdentityProviderReadPermission,
  platformIdentityProviderTestPermission,
  platformIdentityPolicyManagePermission,
  platformIdentityBindingManagePermission,
  platformIdentityBindingReadPermission,
  type PhaseTwoApi,
  type PlatformAuthProviderSummaryView,
  type PlatformAuthProviderView,
  type VersionedView,
} from "../lib/phase-two-types";
import {
  createPlatformAuthProviderDraft,
  derivePlatformAuthProviderDeploymentEndpoints,
  metadataDraftFromProvider,
  platformSamlSignatureAlgorithms,
  toPlatformAuthProviderCreateInput,
  toPlatformAuthProviderUpdateInput,
  validatePlatformAuthProviderAuditReason,
  validatePlatformAuthProviderDraft,
  validatePlatformAuthProviderMetadataDraft,
  validatePlatformOidcClientSecret,
  withPlatformOidcRefreshToken,
  type PlatformAuthProviderDraft,
  type PlatformAuthProviderDeploymentEndpoints,
  type PlatformAuthProviderKind,
  type PlatformAuthProviderMetadataDraft,
  type PlatformSamlSignatureAlgorithm,
  type PlatformSamlSignaturePolicy,
  type PlatformSamlSubjectSource,
} from "./platform-auth-provider-model";
import { PlatformAuthProviderAccounts } from "./platform-auth-provider-accounts";
import { PlatformLdapProviderAdministration } from "./platform-ldap-provider-administration";
import { PlatformAuthProviderSamlMaterials } from "./platform-auth-provider-saml-materials";
import { PlatformAuthProviderTenantBindings } from "./platform-auth-provider-tenant-bindings";
import { LdapProviderEditor } from "./tenant-ldap-providers";

type ProviderListState =
  | { kind: "error"; message: string }
  | { kind: "loading" }
  | {
      items: readonly PlatformAuthProviderSummaryView[];
      kind: "ready";
      nextCursor?: string;
    };

type ProviderDetailState =
  | {
      kind: "error";
      message: string;
      staleValue?: VersionedView<PlatformAuthProviderView>;
    }
  | { kind: "loading"; staleValue?: VersionedView<PlatformAuthProviderView> }
  | { kind: "ready"; value: VersionedView<PlatformAuthProviderView> };

interface MutationNotice {
  message: string;
  tone: "success" | "warning";
}

interface SessionMutationNotice extends MutationNotice {
  sessionId: string;
}

type ProviderActivationAccountMode = "create" | "existing_identity";
type ProviderLifecycleCommand = "activate" | "deactivate";
type ProviderDirectLoginCommand = "activate" | "deactivate";

export function PlatformAuthProvidersPage(): React.JSX.Element {
  const { api, clearSession, session } = useSession();
  const canRead = hasPermission(
    session,
    platformIdentityProviderReadPermission,
  );
  const canManage = hasPermission(
    session,
    platformIdentityProviderManagePermission,
  );
  const canReadBindings = hasPermission(
    session,
    platformIdentityBindingReadPermission,
  );
  const canManageBindings = hasPermission(
    session,
    platformIdentityBindingManagePermission,
  );
  const canReadAccounts = hasPermission(
    session,
    platformIdentityAccountReadPermission,
  );
  const canManageAccounts = hasPermission(
    session,
    platformIdentityAccountManagePermission,
  );
  const canManagePolicy = hasPermission(
    session,
    platformIdentityPolicyManagePermission,
  );
  const canTest = hasPermission(
    session,
    platformIdentityProviderTestPermission,
  );
  const [listState, setListState] = useState<ProviderListState>({
    kind: "loading",
  });
  const [listRevision, setListRevision] = useState(0);
  const [createOpen, setCreateOpen] = useState(false);
  const [selectedProviderId, setSelectedProviderId] = useState<string | null>(
    null,
  );
  const [loadingMore, setLoadingMore] = useState(false);
  const [paginationError, setPaginationError] = useState<string | null>(null);
  const [notice, setNotice] = useState<SessionMutationNotice | null>(null);
  const sessionIdRef = useRef(session.id);
  const cursorHistoryRef = useRef(new Set<string>());
  const listEpochRef = useRef(0);
  const paginationAbortRef = useRef<AbortController | null>(null);
  const paginationLockRef = useRef(false);
  sessionIdRef.current = session.id;
  const visibleNotice = notice?.sessionId === session.id ? notice : null;
  const publishNotice = useCallback(
    (nextNotice: MutationNotice): void => {
      setNotice({ ...nextNotice, sessionId: session.id });
    },
    [session.id],
  );

  const handleRequestError = useCallback(
    (caught: unknown, expectedSessionId: string): "handled" | "unhandled" => {
      if (sessionIdRef.current !== expectedSessionId) return "handled";
      if (caught instanceof PhaseTwoApiError && caught.status === 401) {
        clearSession(expectedSessionId);
        return "handled";
      }
      return "unhandled";
    },
    [clearSession],
  );

  useEffect(() => {
    setCreateOpen(false);
    setSelectedProviderId(null);
    setNotice(null);
    setListState({ kind: "loading" });
    setPaginationError(null);
    setLoadingMore(false);
    paginationAbortRef.current?.abort();
    paginationAbortRef.current = null;
    listEpochRef.current += 1;
    paginationLockRef.current = false;
    cursorHistoryRef.current.clear();
  }, [session.id]);

  useEffect(() => {
    if (canRead) return;
    setCreateOpen(false);
    setSelectedProviderId(null);
    setNotice(null);
    setListState({ kind: "loading" });
    setPaginationError(null);
    setLoadingMore(false);
    paginationAbortRef.current?.abort();
    paginationAbortRef.current = null;
    listEpochRef.current += 1;
    paginationLockRef.current = false;
    cursorHistoryRef.current.clear();
  }, [canRead]);

  useEffect(() => {
    if (!canRead) return undefined;
    paginationAbortRef.current?.abort();
    paginationAbortRef.current = null;
    const controller = new AbortController();
    const expectedSessionId = session.id;
    const listEpoch = listEpochRef.current + 1;
    listEpochRef.current = listEpoch;
    paginationLockRef.current = true;
    cursorHistoryRef.current.clear();
    setLoadingMore(true);
    setListState((current) =>
      current.kind === "ready" ? current : { kind: "loading" },
    );
    setPaginationError(null);
    void api
      .listPlatformAuthProviders({
        includeArchived: true,
        signal: controller.signal,
      })
      .then((page) => {
        if (
          controller.signal.aborted ||
          listEpochRef.current !== listEpoch ||
          sessionIdRef.current !== expectedSessionId
        ) {
          return;
        }
        if (page.nextCursor) cursorHistoryRef.current.add(page.nextCursor);
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
          sessionIdRef.current !== expectedSessionId ||
          isAbortError(caught) ||
          handleRequestError(caught, expectedSessionId) === "handled"
        ) {
          return;
        }
        setListState({
          kind: "error",
          message: describePhaseTwoError(
            caught,
            "The platform identity-provider inventory could not be loaded.",
          ),
        });
      })
      .finally(() => {
        if (
          listEpochRef.current === listEpoch &&
          sessionIdRef.current === expectedSessionId
        ) {
          paginationLockRef.current = false;
          setLoadingMore(false);
        }
      });
    return () => {
      controller.abort();
      paginationAbortRef.current?.abort();
      paginationAbortRef.current = null;
      if (listEpochRef.current === listEpoch) {
        listEpochRef.current += 1;
        paginationLockRef.current = false;
      }
    };
  }, [api, canRead, handleRequestError, listRevision, session.id]);

  async function loadMore(): Promise<void> {
    if (
      listState.kind !== "ready" ||
      !listState.nextCursor ||
      paginationLockRef.current
    ) {
      return;
    }
    const cursor = listState.nextCursor;
    const expectedSessionId = session.id;
    const listEpoch = listEpochRef.current;
    const controller = new AbortController();
    paginationAbortRef.current?.abort();
    paginationAbortRef.current = controller;
    paginationLockRef.current = true;
    setLoadingMore(true);
    setPaginationError(null);
    try {
      const page = await api.listPlatformAuthProviders({
        after: cursor,
        includeArchived: true,
        signal: controller.signal,
      });
      if (
        controller.signal.aborted ||
        sessionIdRef.current !== expectedSessionId ||
        listEpochRef.current !== listEpoch
      ) {
        return;
      }
      if (
        page.nextCursor !== undefined &&
        (page.nextCursor <= cursor ||
          cursorHistoryRef.current.has(page.nextCursor))
      ) {
        throw new Error(
          "The platform identity-provider cursor did not advance.",
        );
      }
      const existingIds = new Set(
        listState.items.map((provider) => provider.id),
      );
      const existingKeys = new Set(
        listState.items.map((provider) => provider.key),
      );
      if (
        page.items.some(
          (provider) =>
            provider.id <= cursor ||
            existingIds.has(provider.id) ||
            existingKeys.has(provider.key),
        )
      ) {
        throw new Error(
          "The platform identity-provider page repeated a provider identity or stable key.",
        );
      }
      if (page.nextCursor) cursorHistoryRef.current.add(page.nextCursor);
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
        sessionIdRef.current !== expectedSessionId ||
        listEpochRef.current !== listEpoch ||
        handleRequestError(caught, expectedSessionId) === "handled"
      ) {
        return;
      }
      setPaginationError(
        describePhaseTwoError(
          caught,
          "More platform identity providers could not be loaded.",
        ),
      );
    } finally {
      if (
        paginationAbortRef.current === controller &&
        sessionIdRef.current === expectedSessionId &&
        listEpochRef.current === listEpoch
      ) {
        paginationAbortRef.current = null;
        paginationLockRef.current = false;
        setLoadingMore(false);
      }
    }
  }

  const refreshList = useCallback((): void => {
    paginationAbortRef.current?.abort();
    paginationAbortRef.current = null;
    listEpochRef.current += 1;
    paginationLockRef.current = true;
    setLoadingMore(true);
    setListRevision((revision) => revision + 1);
  }, []);

  const handleUnauthenticated = useCallback((): void => {
    clearSession(session.id);
  }, [clearSession, session.id]);

  const handlePermissionError = useCallback((): void => {
    publishNotice({
      message:
        "The server denied this action. The displayed permission is not an authorization guarantee; refresh the session before retrying.",
      tone: "warning",
    });
  }, [publishNotice]);

  if (!canRead) {
    if (canReadBindings || canReadAccounts) {
      return (
        <ScopedPlatformAuthProviderPage
          api={api}
          canManageAccounts={canManageAccounts}
          canManageBindings={canManageBindings}
          canReadAccounts={canReadAccounts}
          canReadBindings={canReadBindings}
          csrfToken={session.csrfToken}
          notice={visibleNotice}
          onClearNotice={() => setNotice(null)}
          onNotice={publishNotice}
          onPermissionError={handlePermissionError}
          onUnauthenticated={handleUnauthenticated}
          sessionId={session.id}
        />
      );
    }
    return (
      <div className="content content--narrow">
        <section className="page-heading" aria-labelledby="platform-idp-denied">
          <div>
            <p className="section-label">Platform administration</p>
            <h1 id="platform-idp-denied">
              Global identity providers are not available.
            </h1>
            <p>
              This session did not return the explicit platform
              identity-provider read permission. Tenant identity permissions do
              not grant access.
            </p>
          </div>
        </section>
        <Alert variant="destructive">
          <ShieldX aria-hidden="true" />
          <AlertTitle>Permission not returned</AlertTitle>
          <AlertDescription>
            The API remains the authorization boundary for every request.
          </AlertDescription>
        </Alert>
      </div>
    );
  }

  return (
    <div className="content platform-idp-page">
      <section className="page-heading platform-idp-page__heading">
        <div>
          <p className="section-label">Platform administration</p>
          <h1>Global identity providers</h1>
          <p>
            Manage sanitized OIDC, SAML, and platform-global LDAP definitions.
            Tenant execution and tenantless platform login remain explicit,
            audited boundaries.
          </p>
        </div>
        {canManage ? (
          <Button type="button" onClick={() => setCreateOpen(true)}>
            <Plus aria-hidden="true" /> Create staged provider
          </Button>
        ) : (
          <Badge variant="outline">
            <ShieldCheck aria-hidden="true" /> Read-only authority
          </Badge>
        )}
      </section>

      <ProviderReadinessBand />

      <PlatformIdentityNotice notice={visibleNotice} />

      {listState.kind === "loading" ? <ProviderListSkeleton /> : null}
      {listState.kind === "error" ? (
        <div className="platform-idp-load-error">
          <FocusedError message={listState.message} />
          <Button type="button" variant="outline" onClick={refreshList}>
            <RefreshCw aria-hidden="true" /> Reload inventory
          </Button>
        </div>
      ) : null}
      {listState.kind === "ready" ? (
        <Card className="platform-idp-inventory">
          <CardHeader>
            <CardTitle>Provider inventory</CardTitle>
            <CardDescription>
              List responses contain safe readiness metadata only. Open a row
              for the sanitized protocol configuration.
            </CardDescription>
          </CardHeader>
          <CardContent>
            {listState.items.length === 0 ? (
              <div className="platform-idp-empty">
                <Fingerprint aria-hidden="true" />
                <h2>No global providers recorded</h2>
                <p>
                  Create an OIDC, SAML, or LDAP definition without activating
                  login.
                </p>
              </div>
            ) : (
              <div className="platform-idp-table-wrap">
                <Table className="platform-idp-table">
                  <TableCaption>
                    Tenant execution and direct platform login are separate;
                    each requires its own explicit activation.
                  </TableCaption>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Provider</TableHead>
                      <TableHead>Protocol</TableHead>
                      <TableHead>Configuration</TableHead>
                      <TableHead>Protected material</TableHead>
                      <TableHead>State</TableHead>
                      <TableHead className="text-right">Action</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {listState.items.map((provider) => (
                      <TableRow key={provider.id}>
                        <TableCell>
                          <div className="platform-idp-provider-cell">
                            <strong>{provider.displayName}</strong>
                            <code>{provider.key}</code>
                          </div>
                        </TableCell>
                        <TableCell>{kindLabel(provider.kind)}</TableCell>
                        <TableCell>
                          {provider.configured ? "Recorded" : "Incomplete"}
                        </TableCell>
                        <TableCell>
                          {provider.kind === "saml"
                            ? "Not applicable"
                            : provider.secretPresent
                              ? "Present"
                              : "Not set"}
                        </TableCell>
                        <TableCell>
                          <ProviderStateBadge provider={provider} />
                        </TableCell>
                        <TableCell className="text-right">
                          <Button
                            type="button"
                            size="sm"
                            variant="outline"
                            aria-label={`Inspect ${provider.displayName} (${provider.key})`}
                            onClick={() => setSelectedProviderId(provider.id)}
                          >
                            Inspect
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
            {paginationError ? (
              <FocusedError autoFocus={false} message={paginationError} />
            ) : null}
            {listState.nextCursor ? (
              <div className="platform-idp-pagination">
                <Button
                  type="button"
                  variant="outline"
                  disabled={loadingMore}
                  onClick={() => void loadMore()}
                >
                  {loadingMore ? "Loading…" : "Load more providers"}
                </Button>
              </div>
            ) : null}
          </CardContent>
        </Card>
      ) : null}

      <CreateProviderDialog
        api={api}
        canManage={canManage}
        csrfToken={session.csrfToken}
        onCreated={(provider) => {
          if (provider.archivedAt !== null) {
            publishNotice({
              message: `${provider.displayName} is already archived. The safe retry returned its current state and did not recreate or activate the provider.`,
              tone: "warning",
            });
          } else if (provider.kind === "ldap" && provider.enabled) {
            publishNotice({
              message: `${provider.displayName} already has tenantless LDAP login enabled. Existing-identity and TOTP enforcement remain server-side.`,
              tone: "warning",
            });
          } else if (provider.enabled) {
            publishNotice({
              message: `${provider.displayName} is already active for tenant execution. The safe retry returned its current state and left direct platform login ${provider.platformLoginEnabled ? "active" : "disabled"}.`,
              tone: "warning",
            });
          } else if (provider.activationAvailable) {
            publishNotice({
              message: `${provider.displayName} is already ready for tenant-execution activation. The safe retry returned its current state without activating either login boundary.`,
              tone: "warning",
            });
          } else if (provider.version > 1) {
            publishNotice({
              message: `${provider.displayName} already exists and is currently disabled. The safe retry returned its later version without recreating or activating the provider.`,
              tone: "warning",
            });
          } else {
            publishNotice({
              message: `${provider.displayName} was staged disabled. Platform login remains blocked.`,
              tone: "success",
            });
          }
          setCreateOpen(false);
          setSelectedProviderId(provider.id);
          refreshList();
        }}
        onConflict={() => {
          publishNotice({
            message:
              "The create request conflicted with current state. Exact replay is bounded to 24 hours; the authorized provider inventory is being reloaded before a new attempt.",
            tone: "warning",
          });
          setCreateOpen(false);
          refreshList();
        }}
        onOpenChange={setCreateOpen}
        onPermissionError={handlePermissionError}
        onUnauthenticated={handleUnauthenticated}
        open={createOpen}
        sessionId={session.id}
      />

      <ProviderDetailDialog
        api={api}
        canManageAccounts={canManageAccounts}
        canManageBindings={canManageBindings}
        canReadAccounts={canReadAccounts}
        canReadBindings={canReadBindings}
        canManage={canManage}
        canManagePolicy={canManagePolicy}
        canRead={canRead}
        canTest={canTest}
        csrfToken={session.csrfToken}
        onArchived={(providerName) => {
          publishNotice({
            message: `${providerName} was archived. It remains unavailable for platform login.`,
            tone: "success",
          });
          setSelectedProviderId(null);
          refreshList();
        }}
        onChanged={refreshList}
        onNotice={publishNotice}
        onOpenChange={(open) => {
          if (!open) setSelectedProviderId(null);
        }}
        onPermissionError={handlePermissionError}
        onUnauthenticated={handleUnauthenticated}
        open={selectedProviderId !== null}
        providerId={selectedProviderId}
        sessionId={session.id}
      />
    </div>
  );
}

interface ScopedPlatformAuthProviderPageProps {
  api: PhaseTwoApi;
  canManageAccounts: boolean;
  canManageBindings: boolean;
  canReadAccounts: boolean;
  canReadBindings: boolean;
  csrfToken: string;
  notice: MutationNotice | null;
  onClearNotice: () => void;
  onNotice: (notice: MutationNotice) => void;
  onPermissionError: () => void;
  onUnauthenticated: () => void;
  sessionId: string;
}

function ScopedPlatformAuthProviderPage({
  api,
  canManageAccounts,
  canManageBindings,
  canReadAccounts,
  canReadBindings,
  csrfToken,
  notice,
  onClearNotice,
  onNotice,
  onPermissionError,
  onUnauthenticated,
  sessionId,
}: ScopedPlatformAuthProviderPageProps): React.JSX.Element {
  const providerIdInputId = useId();
  const [providerIdDraft, setProviderIdDraft] = useState("");
  const [providerId, setProviderId] = useState<string | null>(null);
  const [providerIdError, setProviderIdError] = useState<string | null>(null);
  const [accountMutationBusy, setAccountMutationBusy] = useState(false);
  const [bindingMutationBusy, setBindingMutationBusy] = useState(false);

  const mutationBusy = accountMutationBusy || bindingMutationBusy;
  const bindingOnly = canReadBindings && !canReadAccounts;
  const accountOnly = canReadAccounts && !canReadBindings;
  const pageTitle = bindingOnly
    ? "Tenant bindings by provider ID"
    : accountOnly
      ? "Linked platform accounts by provider ID"
      : "Provider-scoped identity records";
  const authorityLabel = bindingOnly
    ? "Binding-only authority"
    : accountOnly
      ? "Account-only authority"
      : "Scoped identity authority";
  const inventoryTitle = bindingOnly
    ? "Open tenant-binding inventory"
    : accountOnly
      ? "Open account register"
      : "Open provider-scoped records";

  useEffect(() => {
    setProviderIdDraft("");
    setProviderId(null);
    setProviderIdError(null);
    setAccountMutationBusy(false);
    setBindingMutationBusy(false);
  }, [sessionId]);

  function openBindings(event: React.FormEvent<HTMLFormElement>): void {
    event.preventDefault();
    if (!canonicalUuidV7Pattern.test(providerIdDraft)) {
      setProviderIdError("Platform provider ID must be a canonical UUIDv7.");
      return;
    }
    setProviderIdError(null);
    setProviderId(providerIdDraft);
  }

  return (
    <div className="content platform-idp-page">
      <section className="page-heading platform-idp-page__heading">
        <div>
          <p className="section-label">Platform administration</p>
          <h1>{pageTitle}</h1>
          <p>
            Inspect or manage explicitly authorized identity records without
            exposing the provider inventory or its protocol configuration.
          </p>
        </div>
        <Badge variant="outline">
          <ShieldCheck aria-hidden="true" /> {authorityLabel}
        </Badge>
      </section>

      <Alert>
        <ShieldAlert aria-hidden="true" />
        <AlertTitle>Provider metadata permission not returned</AlertTitle>
        <AlertDescription>
          Enter a known platform-provider UUIDv7. Every account and binding
          request is authorized independently by the API, and provider lifecycle
          checks remain server-enforced.
        </AlertDescription>
      </Alert>

      <PlatformIdentityNotice notice={notice} />

      <Card>
        <CardHeader>
          <CardTitle>{inventoryTitle}</CardTitle>
          <CardDescription>
            The identifier is used only as the explicit API scope; it does not
            reveal provider metadata.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form
            className="platform-idp-action-form"
            aria-label={`Open ${
              bindingOnly
                ? "tenant bindings"
                : accountOnly
                  ? "linked platform accounts"
                  : "provider-scoped identity records"
            } by provider ID`}
            onSubmit={openBindings}
          >
            <FormField
              {...(providerIdError ? { error: providerIdError } : {})}
              htmlFor={providerIdInputId}
              hint="Canonical UUIDv7 of the platform identity provider."
              label="Platform provider ID"
            >
              <Input
                aria-describedby={`${providerIdInputId}-${providerIdError ? "error" : "hint"}`}
                aria-invalid={providerIdError ? true : undefined}
                id={providerIdInputId}
                autoComplete="off"
                disabled={mutationBusy}
                spellCheck={false}
                value={providerIdDraft}
                onChange={(event) => {
                  const nextProviderId = event.target.value;
                  setProviderIdDraft(nextProviderId);
                  if (providerId !== nextProviderId) {
                    setProviderId(null);
                    onClearNotice();
                  }
                  setProviderIdError(null);
                }}
              />
            </FormField>
            <Button type="submit" disabled={mutationBusy}>
              {bindingOnly
                ? "Open tenant bindings"
                : accountOnly
                  ? "Open account register"
                  : "Open identity records"}
            </Button>
          </form>
        </CardContent>
      </Card>

      {providerId && canReadBindings ? (
        <PlatformAuthProviderTenantBindings
          api={api}
          canManage={canManageBindings}
          canRead={true}
          csrfToken={csrfToken}
          onMutationBusyChange={setBindingMutationBusy}
          onNotice={onNotice}
          onPermissionError={onPermissionError}
          onUnauthenticated={onUnauthenticated}
          providerArchived={false}
          providerMutationBusy={accountMutationBusy}
          providerId={providerId}
          sessionId={sessionId}
        />
      ) : null}

      {providerId && canReadAccounts ? (
        <PlatformAuthProviderAccounts
          allowWriteOnlyIssuer={true}
          api={api}
          canManage={canManageAccounts}
          canRead={true}
          csrfToken={csrfToken}
          onMutationBusyChange={setAccountMutationBusy}
          onNotice={onNotice}
          onPermissionError={onPermissionError}
          onUnauthenticated={onUnauthenticated}
          providerId={providerId}
          providerMutationBusy={bindingMutationBusy}
          providerVersion={0}
          sessionId={sessionId}
        />
      ) : null}
    </div>
  );
}

function PlatformIdentityNotice({
  notice,
}: {
  notice: MutationNotice | null;
}): React.JSX.Element | null {
  if (!notice) return null;
  return (
    <Alert className="platform-idp-notice">
      {notice.tone === "success" ? (
        <CheckCircle2 aria-hidden="true" />
      ) : (
        <ShieldAlert aria-hidden="true" />
      )}
      <AlertTitle>
        {notice.tone === "success" ? "Change recorded" : "Review required"}
      </AlertTitle>
      <AlertDescription>{notice.message}</AlertDescription>
    </Alert>
  );
}

const canonicalUuidV7Pattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

interface CreateProviderDialogProps {
  api: PhaseTwoApi;
  canManage: boolean;
  csrfToken: string;
  onCreated: (provider: PlatformAuthProviderView) => void;
  onConflict: () => void;
  onOpenChange: (open: boolean) => void;
  onPermissionError: () => void;
  onUnauthenticated: () => void;
  open: boolean;
  sessionId: string;
}

function CreateProviderDialog({
  api,
  canManage,
  csrfToken,
  onCreated,
  onConflict,
  onOpenChange,
  onPermissionError,
  onUnauthenticated,
  open,
  sessionId,
}: CreateProviderDialogProps): React.JSX.Element {
  const [draft, setDraft] = useState<PlatformAuthProviderDraft>(() =>
    createPlatformAuthProviderDraft("oidc"),
  );
  const deploymentEndpoints = derivePlatformAuthProviderDeploymentEndpoints(
    readBrowserPublicOrigin(),
    draft.key,
  );
  const [errors, setErrors] = useState<readonly string[]>([]);
  const [requestError, setRequestError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const requestSessionRef = useRef(sessionId);
  const mountedRef = useRef(false);
  const idempotencyBindingRef = useRef<{
    fingerprint: string;
    key: string;
  } | null>(null);
  const submitLockRef = useRef<symbol | null>(null);
  const submitContextRef = useRef({
    canManage,
    epoch: 0,
    open,
    sessionId,
  });
  const previousSubmitContext = submitContextRef.current;
  if (
    previousSubmitContext.canManage !== canManage ||
    previousSubmitContext.open !== open ||
    previousSubmitContext.sessionId !== sessionId
  ) {
    submitContextRef.current = {
      canManage,
      epoch: previousSubmitContext.epoch + 1,
      open,
      sessionId,
    };
    submitLockRef.current = null;
  }
  requestSessionRef.current = sessionId;

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      const context = submitContextRef.current;
      submitContextRef.current = {
        ...context,
        epoch: context.epoch + 1,
        open: false,
      };
      submitLockRef.current = null;
    };
  }, []);

  useEffect(() => {
    if (!open) {
      setDraft(createPlatformAuthProviderDraft("oidc"));
      setErrors([]);
      setRequestError(null);
      setSubmitting(false);
      idempotencyBindingRef.current = null;
      submitLockRef.current = null;
    }
  }, [open, sessionId]);

  useEffect(() => {
    if (!canManage && open) onOpenChange(false);
  }, [canManage, onOpenChange, open]);

  function changeKind(kind: PlatformAuthProviderKind): void {
    if (submitLockRef.current !== null || draft.kind === kind) return;
    const next = createPlatformAuthProviderDraft(kind);
    setDraft({
      ...next,
      auditReason: draft.auditReason,
      description: draft.description,
      displayName: draft.displayName,
      key: draft.key,
    });
    setErrors([]);
    setRequestError(null);
  }

  function submissionIsCurrent(
    epoch: number,
    expectedSessionId: string,
    token: symbol,
  ): boolean {
    const context = submitContextRef.current;
    return (
      mountedRef.current &&
      submitLockRef.current === token &&
      context.epoch === epoch &&
      context.canManage &&
      context.open &&
      context.sessionId === expectedSessionId
    );
  }

  async function submit(
    event: React.FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault();
    if (!canManage || submitLockRef.current !== null) return;
    const validationErrors = validatePlatformAuthProviderDraft(
      draft,
      deploymentEndpoints,
    );
    setErrors(validationErrors);
    setRequestError(null);
    if (
      validationErrors.length > 0 ||
      (draft.kind !== "ldap" && deploymentEndpoints === null)
    ) {
      return;
    }
    const input = toPlatformAuthProviderCreateInput(draft, deploymentEndpoints);
    const idempotencyKey = idempotencyKeyForPayload(idempotencyBindingRef, {
      auditReason: draft.auditReason,
      input,
    });
    const expectedSessionId = sessionId;
    const submitEpoch = submitContextRef.current.epoch;
    const submitToken = Symbol("platform-provider-create");
    submitLockRef.current = submitToken;
    setSubmitting(true);
    try {
      const created = await api.createPlatformAuthProvider(
        csrfToken,
        idempotencyKey,
        draft.auditReason,
        input,
      );
      if (!submissionIsCurrent(submitEpoch, expectedSessionId, submitToken)) {
        return;
      }
      idempotencyBindingRef.current = null;
      onCreated(created.value);
    } catch (caught) {
      if (!submissionIsCurrent(submitEpoch, expectedSessionId, submitToken)) {
        return;
      }
      if (caught instanceof PhaseTwoApiError && caught.status === 401) {
        onUnauthenticated();
        return;
      }
      if (caught instanceof PhaseTwoApiError && caught.status === 403) {
        onPermissionError();
      }
      if (caught instanceof PhaseTwoApiError && caught.status === 409) {
        idempotencyBindingRef.current = null;
        setErrors([]);
        setRequestError(null);
        onConflict();
        return;
      }
      setRequestError(
        describePhaseTwoError(
          caught,
          "The provider was not created. An unchanged request can be retried with the same idempotency key.",
        ),
      );
    } finally {
      if (submitLockRef.current === submitToken) {
        submitLockRef.current = null;
        if (requestSessionRef.current === expectedSessionId) {
          setSubmitting(false);
        }
      }
    }
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (submitLockRef.current === null) onOpenChange(next);
      }}
    >
      <DialogContent className="platform-idp-create-dialog">
        <DialogHeader>
          <DialogTitle>Create staged identity provider</DialogTitle>
          <DialogDescription>
            Record a typed, non-secret definition. Provider execution, account
            mode, and platform login are fixed disabled.
          </DialogDescription>
        </DialogHeader>
        <fieldset
          aria-busy={submitting}
          className="platform-idp-create-lock"
          disabled={submitting}
        >
          <div
            className="platform-idp-kind-picker"
            role="group"
            aria-label="Provider protocol"
          >
            <button
              className={
                draft.kind === "oidc"
                  ? "platform-idp-kind-card platform-idp-kind-card--active"
                  : "platform-idp-kind-card"
              }
              aria-pressed={draft.kind === "oidc"}
              disabled={submitting}
              type="button"
              onClick={() => changeKind("oidc")}
            >
              <KeyRound aria-hidden="true" />
              <span>
                <strong>OIDC</strong>
                <small>Discovery coordinates; secret set later</small>
              </span>
            </button>
            <button
              className={
                draft.kind === "saml"
                  ? "platform-idp-kind-card platform-idp-kind-card--active"
                  : "platform-idp-kind-card"
              }
              aria-pressed={draft.kind === "saml"}
              disabled={submitting}
              type="button"
              onClick={() => changeKind("saml")}
            >
              <Fingerprint aria-hidden="true" />
              <span>
                <strong>SAML 2.0</strong>
                <small>Trust coordinates; encryption unavailable</small>
              </span>
            </button>
            <button
              className={
                draft.kind === "ldap"
                  ? "platform-idp-kind-card platform-idp-kind-card--active"
                  : "platform-idp-kind-card"
              }
              aria-pressed={draft.kind === "ldap"}
              disabled={submitting}
              type="button"
              onClick={() => changeKind("ldap")}
            >
              <Network aria-hidden="true" />
              <span>
                <strong>LDAP</strong>
                <small>Existing identities + mandatory TOTP</small>
              </span>
            </button>
          </div>
          <form
            className="platform-idp-form"
            aria-label="Create staged identity provider"
            onSubmit={(event) => void submit(event)}
          >
            {draft.kind === "ldap" ? (
              <LdapProviderEditor
                draft={draft}
                mode="create"
                policy="platform_global"
                onChange={(nextDraft) => {
                  if (submitLockRef.current === null) {
                    setDraft({
                      ...nextDraft,
                      auditReason: draft.auditReason,
                      kind: "ldap",
                    });
                  }
                }}
              />
            ) : (
              <>
                <MetadataFields
                  draft={draft}
                  onChange={(patch) => {
                    if (submitLockRef.current === null) {
                      setDraft({ ...draft, ...patch });
                    }
                  }}
                  prefix="platform-idp-create"
                />
                {draft.kind === "oidc" ? (
                  <OidcCreateFields
                    deploymentEndpoints={deploymentEndpoints}
                    draft={draft}
                    onChange={(nextDraft) => {
                      if (submitLockRef.current === null) setDraft(nextDraft);
                    }}
                  />
                ) : (
                  <SamlCreateFields
                    deploymentEndpoints={deploymentEndpoints}
                    draft={draft}
                    onChange={(nextDraft) => {
                      if (submitLockRef.current === null) setDraft(nextDraft);
                    }}
                  />
                )}
              </>
            )}
            <AuditReasonField
              id="platform-idp-create-reason"
              value={draft.auditReason}
              onChange={(auditReason) => {
                if (submitLockRef.current === null) {
                  setDraft({ ...draft, auditReason });
                }
              }}
            />
            {errors.length > 0 ? <ValidationSummary errors={errors} /> : null}
            {requestError ? <FocusedError message={requestError} /> : null}
            <DialogFooter>
              <Button
                type="button"
                variant="outline"
                disabled={submitting}
                onClick={() => onOpenChange(false)}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={submitting || !canManage}>
                <Plus aria-hidden="true" />
                {submitting ? "Creating…" : "Create disabled provider"}
              </Button>
            </DialogFooter>
          </form>
        </fieldset>
      </DialogContent>
    </Dialog>
  );
}

interface ProviderDetailDialogProps {
  api: PhaseTwoApi;
  canManageAccounts: boolean;
  canManageBindings: boolean;
  canReadAccounts: boolean;
  canReadBindings: boolean;
  canManage: boolean;
  canManagePolicy: boolean;
  canRead: boolean;
  canTest: boolean;
  csrfToken: string;
  onArchived: (providerName: string) => void;
  onChanged: () => void;
  onNotice: (notice: MutationNotice) => void;
  onOpenChange: (open: boolean) => void;
  onPermissionError: () => void;
  onUnauthenticated: () => void;
  open: boolean;
  providerId: string | null;
  sessionId: string;
}

function ProviderDetailDialog({
  api,
  canManageAccounts,
  canManageBindings,
  canReadAccounts,
  canReadBindings,
  canManage,
  canManagePolicy,
  canRead,
  canTest,
  csrfToken,
  onArchived,
  onChanged,
  onNotice,
  onOpenChange,
  onPermissionError,
  onUnauthenticated,
  open,
  providerId,
  sessionId,
}: ProviderDetailDialogProps): React.JSX.Element {
  const [state, setState] = useState<ProviderDetailState>({ kind: "loading" });
  const [refreshRevision, setRefreshRevision] = useState(0);
  const [metadataDraft, setMetadataDraft] =
    useState<PlatformAuthProviderMetadataDraft | null>(null);
  const [metadataErrors, setMetadataErrors] = useState<readonly string[]>([]);
  const [metadataConflict, setMetadataConflict] = useState(false);
  const [secretOpen, setSecretOpen] = useState(false);
  const [clientSecret, setClientSecret] = useState("");
  const [secretReason, setSecretReason] = useState("");
  const [archiveOpen, setArchiveOpen] = useState(false);
  const [archiveReason, setArchiveReason] = useState("");
  const [archiveConfirmation, setArchiveConfirmation] = useState("");
  const [lifecycleCommand, setLifecycleCommand] =
    useState<ProviderLifecycleCommand | null>(null);
  const [lifecycleReason, setLifecycleReason] = useState("");
  const [lifecycleConfirmation, setLifecycleConfirmation] = useState("");
  const [directLoginCommand, setDirectLoginCommand] =
    useState<ProviderDirectLoginCommand | null>(null);
  const [directLoginReason, setDirectLoginReason] = useState("");
  const [directLoginConfirmation, setDirectLoginConfirmation] = useState("");
  const [accountMode, setAccountMode] =
    useState<ProviderActivationAccountMode>("existing_identity");
  const [mutationError, setMutationError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState<
    | "activate"
    | "activate-direct-login"
    | "archive"
    | "deactivate"
    | "deactivate-direct-login"
    | "metadata"
    | "secret"
    | null
  >(null);
  const [bindingMutationBusy, setBindingMutationBusy] = useState(false);
  const [accountMutationBusy, setAccountMutationBusy] = useState(false);
  const [samlMutationBusy, setSamlMutationBusy] = useState(false);
  const [bindingRefreshRevision, setBindingRefreshRevision] = useState(0);
  const sessionRef = useRef(sessionId);
  const mountedRef = useRef(false);
  const mutationLockRef = useRef<symbol | null>(null);
  const mutationContextRef = useRef({
    canManage,
    canRead,
    epoch: 0,
    open,
    providerId,
    sessionId,
  });
  const previousContext = mutationContextRef.current;
  if (
    previousContext.canManage !== canManage ||
    previousContext.canRead !== canRead ||
    previousContext.open !== open ||
    previousContext.providerId !== providerId ||
    previousContext.sessionId !== sessionId
  ) {
    mutationContextRef.current = {
      canManage,
      canRead,
      epoch: previousContext.epoch + 1,
      open,
      providerId,
      sessionId,
    };
    mutationLockRef.current = null;
  }
  sessionRef.current = sessionId;

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      const context = mutationContextRef.current;
      mutationContextRef.current = {
        ...context,
        epoch: context.epoch + 1,
        open: false,
      };
      mutationLockRef.current = null;
    };
  }, []);

  useEffect(() => {
    setState({ kind: "loading" });
    setMetadataDraft(null);
    setMetadataErrors([]);
    setMetadataConflict(false);
    setSecretOpen(false);
    setClientSecret("");
    setSecretReason("");
    setArchiveOpen(false);
    setArchiveReason("");
    setArchiveConfirmation("");
    setLifecycleCommand(null);
    setLifecycleReason("");
    setLifecycleConfirmation("");
    setDirectLoginCommand(null);
    setDirectLoginReason("");
    setDirectLoginConfirmation("");
    setAccountMode("existing_identity");
    setMutationError(null);
    setSubmitting(null);
    setBindingMutationBusy(false);
    setAccountMutationBusy(false);
    setSamlMutationBusy(false);
    mutationLockRef.current = null;
  }, [open, providerId, sessionId]);

  useEffect(() => {
    if (canManage && canRead) return;
    setMetadataDraft(null);
    setMetadataErrors([]);
    setMetadataConflict(false);
    setSecretOpen(false);
    setClientSecret("");
    setSecretReason("");
    setArchiveOpen(false);
    setArchiveReason("");
    setArchiveConfirmation("");
    setLifecycleCommand(null);
    setLifecycleReason("");
    setLifecycleConfirmation("");
    setDirectLoginCommand(null);
    setDirectLoginReason("");
    setDirectLoginConfirmation("");
    setAccountMode("existing_identity");
    setMutationError(null);
    setSubmitting(null);
    setSamlMutationBusy(false);
    mutationLockRef.current = null;
  }, [canManage, canRead]);

  useEffect(() => {
    if (!open || !providerId || !canRead) return undefined;
    const controller = new AbortController();
    const expectedSessionId = sessionId;
    setState((current) => {
      const staleValue =
        current.kind === "ready"
          ? current.value
          : "staleValue" in current
            ? current.staleValue
            : undefined;
      return { kind: "loading", ...(staleValue ? { staleValue } : {}) };
    });
    void api
      .getPlatformAuthProvider(providerId, controller.signal)
      .then((provider) => {
        if (
          controller.signal.aborted ||
          sessionRef.current !== expectedSessionId
        ) {
          return;
        }
        setState({ kind: "ready", value: provider });
      })
      .catch((caught: unknown) => {
        if (
          controller.signal.aborted ||
          sessionRef.current !== expectedSessionId ||
          isAbortError(caught)
        ) {
          return;
        }
        if (caught instanceof PhaseTwoApiError && caught.status === 401) {
          onUnauthenticated();
          return;
        }
        const forbidden =
          caught instanceof PhaseTwoApiError && caught.status === 403;
        if (forbidden) {
          onPermissionError();
        }
        setState((current) => {
          const staleValue =
            current.kind === "ready"
              ? current.value
              : "staleValue" in current
                ? current.staleValue
                : undefined;
          return {
            kind: "error",
            message: describePhaseTwoError(
              caught,
              "The sanitized provider detail could not be loaded.",
            ),
            ...(!forbidden && staleValue ? { staleValue } : {}),
          };
        });
      });
    return () => controller.abort();
  }, [
    api,
    canRead,
    onPermissionError,
    onUnauthenticated,
    open,
    providerId,
    refreshRevision,
    sessionId,
  ]);

  const coherentVersioned = state.kind === "ready" ? state.value : undefined;
  const staleVersioned =
    state.kind !== "ready" && "staleValue" in state
      ? state.staleValue
      : undefined;
  const displayVersioned = coherentVersioned ?? staleVersioned;
  const provider = displayVersioned?.value;

  function markProjectionStale(): void {
    if (coherentVersioned) {
      setState({ kind: "loading", staleValue: coherentVersioned });
    }
    setRefreshRevision((revision) => revision + 1);
  }

  function mutationIsCurrent(
    epoch: number,
    expectedProviderId: string,
    expectedSessionId: string,
    token: symbol,
  ): boolean {
    const context = mutationContextRef.current;
    return (
      mountedRef.current &&
      mutationLockRef.current === token &&
      context.epoch === epoch &&
      context.canManage &&
      context.canRead &&
      context.open &&
      context.providerId === expectedProviderId &&
      context.sessionId === expectedSessionId
    );
  }

  function releaseMutation(token: symbol, expectedSessionId: string): void {
    if (!mountedRef.current || mutationLockRef.current !== token) return;
    mutationLockRef.current = null;
    if (sessionRef.current === expectedSessionId) setSubmitting(null);
  }

  function handleMutationFailure(caught: unknown, fallback: string): void {
    if (caught instanceof PhaseTwoApiError && caught.status === 401) {
      onUnauthenticated();
      return;
    }
    if (caught instanceof PhaseTwoApiError && caught.status === 403) {
      onPermissionError();
    }
    if (
      caught instanceof PhaseTwoApiError &&
      (caught.status === 409 || caught.status === 412)
    ) {
      if (metadataDraft !== null) setMetadataConflict(true);
      setBindingRefreshRevision((revision) => revision + 1);
      markProjectionStale();
    }
    setMutationError(describePhaseTwoError(caught, fallback));
  }

  async function updateMetadata(
    event: React.FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault();
    if (
      !canManage ||
      !providerId ||
      !metadataDraft ||
      !coherentVersioned ||
      bindingMutationBusy ||
      accountMutationBusy ||
      samlMutationBusy ||
      mutationLockRef.current !== null ||
      metadataConflict
    ) {
      return;
    }
    const errors = validatePlatformAuthProviderMetadataDraft(metadataDraft);
    setMetadataErrors(errors);
    setMutationError(null);
    if (errors.length > 0) return;
    const expectedSessionId = sessionId;
    const expectedProviderId = providerId;
    const mutationEpoch = mutationContextRef.current.epoch;
    const mutationToken = Symbol("platform-provider-metadata");
    mutationLockRef.current = mutationToken;
    setSubmitting("metadata");
    try {
      const updated = await api.updatePlatformAuthProvider(
        csrfToken,
        providerId,
        coherentVersioned,
        metadataDraft.auditReason,
        toPlatformAuthProviderUpdateInput(
          metadataDraft,
          coherentVersioned.value.version,
        ),
      );
      if (
        !mutationIsCurrent(
          mutationEpoch,
          expectedProviderId,
          expectedSessionId,
          mutationToken,
        )
      ) {
        return;
      }
      setState({ kind: "ready", value: updated });
      setMetadataDraft(null);
      setMetadataErrors([]);
      setMetadataConflict(false);
      onChanged();
      onNotice({
        message: `${updated.value.displayName} metadata was replaced at version ${updated.value.version}; tenant execution remains ${updated.value.enabled ? "active" : "disabled"} and direct platform login remains ${updated.value.platformLoginEnabled ? "active" : "disabled"}.`,
        tone: "success",
      });
    } catch (caught) {
      if (
        !mutationIsCurrent(
          mutationEpoch,
          expectedProviderId,
          expectedSessionId,
          mutationToken,
        )
      ) {
        return;
      }
      handleMutationFailure(
        caught,
        "The provider metadata was not replaced. Review the current server version.",
      );
    } finally {
      releaseMutation(mutationToken, expectedSessionId);
    }
  }

  async function replaceClientSecret(
    event: React.FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault();
    if (
      !canManage ||
      !providerId ||
      !coherentVersioned ||
      coherentVersioned.value.kind !== "oidc" ||
      bindingMutationBusy ||
      accountMutationBusy ||
      samlMutationBusy ||
      mutationLockRef.current !== null
    ) {
      return;
    }
    const errors = [
      validatePlatformOidcClientSecret(clientSecret),
      validatePlatformAuthProviderAuditReason(secretReason),
    ].filter((error): error is string => error !== null);
    setMutationError(errors[0] ?? null);
    if (errors.length > 0) return;
    const secretForRequest = clientSecret;
    const expectedSessionId = sessionId;
    const expectedProviderId = providerId;
    const mutationEpoch = mutationContextRef.current.epoch;
    const mutationToken = Symbol("platform-provider-secret");
    mutationLockRef.current = mutationToken;
    setClientSecret("");
    setSubmitting("secret");
    try {
      await api.replacePlatformOidcAuthProviderClientSecret(
        csrfToken,
        providerId,
        coherentVersioned.etag,
        secretReason,
        {
          clientSecret: secretForRequest,
          expectedVersion: coherentVersioned.value.version,
        },
      );
      if (
        !mutationIsCurrent(
          mutationEpoch,
          expectedProviderId,
          expectedSessionId,
          mutationToken,
        )
      ) {
        return;
      }
      setSecretOpen(false);
      setSecretReason("");
      setMutationError(null);
      markProjectionStale();
      onChanged();
      onNotice({
        message:
          "The OIDC client secret was replaced write-only. No secret value was returned or retained in the form.",
        tone: "success",
      });
    } catch (caught) {
      if (
        !mutationIsCurrent(
          mutationEpoch,
          expectedProviderId,
          expectedSessionId,
          mutationToken,
        )
      ) {
        return;
      }
      handleMutationFailure(
        caught,
        "The write-only OIDC client secret was not replaced. Re-enter it before retrying.",
      );
    } finally {
      releaseMutation(mutationToken, expectedSessionId);
    }
  }

  async function changeProviderExecution(
    event: React.FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault();
    if (
      !canManage ||
      !providerId ||
      !coherentVersioned ||
      lifecycleCommand === null ||
      bindingMutationBusy ||
      accountMutationBusy ||
      samlMutationBusy ||
      mutationLockRef.current !== null ||
      coherentVersioned.value.archivedAt !== null ||
      (lifecycleCommand === "activate" &&
        (coherentVersioned.value.enabled ||
          !coherentVersioned.value.activationAvailable)) ||
      (lifecycleCommand === "deactivate" && !coherentVersioned.value.enabled) ||
      (lifecycleCommand === "deactivate" &&
        coherentVersioned.value.platformLoginEnabled)
    ) {
      return;
    }
    const reasonError =
      validatePlatformAuthProviderAuditReason(lifecycleReason);
    if (reasonError || lifecycleConfirmation !== coherentVersioned.value.key) {
      setMutationError(
        reasonError ??
          `Type ${coherentVersioned.value.key} to confirm ${lifecycleCommand}.`,
      );
      return;
    }
    const expectedSessionId = sessionId;
    const expectedProviderId = providerId;
    const mutationEpoch = mutationContextRef.current.epoch;
    const command = lifecycleCommand;
    const mutationToken = Symbol(`platform-provider-${command}`);
    mutationLockRef.current = mutationToken;
    setMutationError(null);
    setSubmitting(command);
    try {
      const updated =
        command === "activate"
          ? await api.activatePlatformAuthProvider(
              csrfToken,
              providerId,
              coherentVersioned,
              lifecycleReason,
              {
                accountMode,
                expectedVersion: coherentVersioned.value.version,
              },
            )
          : await api.deactivatePlatformAuthProvider(
              csrfToken,
              providerId,
              coherentVersioned,
              lifecycleReason,
              { expectedVersion: coherentVersioned.value.version },
            );
      if (
        !mutationIsCurrent(
          mutationEpoch,
          expectedProviderId,
          expectedSessionId,
          mutationToken,
        )
      ) {
        return;
      }
      setState({ kind: "ready", value: updated });
      setLifecycleCommand(null);
      setLifecycleReason("");
      setLifecycleConfirmation("");
      setAccountMode("existing_identity");
      setBindingRefreshRevision((revision) => revision + 1);
      onChanged();
      onNotice({
        message:
          command === "activate"
            ? `${updated.value.displayName} tenant execution is active in ${humanizeToken(updated.value.accountMode)} mode. Direct platform login is unchanged and remains disabled.`
            : `${updated.value.displayName} tenant execution was deactivated. Direct platform login is unchanged and remains disabled.`,
        tone: "success",
      });
    } catch (caught) {
      if (
        !mutationIsCurrent(
          mutationEpoch,
          expectedProviderId,
          expectedSessionId,
          mutationToken,
        )
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
      }
      handleMutationFailure(
        caught,
        `The provider was not ${command}d. Review the refreshed server version and readiness.`,
      );
    } finally {
      releaseMutation(mutationToken, expectedSessionId);
    }
  }

  async function changeDirectLogin(
    event: React.FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault();
    if (
      !canManage ||
      !providerId ||
      !coherentVersioned ||
      directLoginCommand === null ||
      bindingMutationBusy ||
      accountMutationBusy ||
      samlMutationBusy ||
      mutationLockRef.current !== null ||
      coherentVersioned.value.archivedAt !== null ||
      !coherentVersioned.value.enabled ||
      !coherentVersioned.value.configured ||
      !coherentVersioned.value.secretPresent ||
      (directLoginCommand === "activate"
        ? coherentVersioned.value.platformLoginEnabled ||
          !coherentVersioned.value.platformLoginActivationAvailable
        : !coherentVersioned.value.platformLoginEnabled)
    ) {
      return;
    }
    const reasonError =
      validatePlatformAuthProviderAuditReason(directLoginReason);
    if (
      reasonError ||
      directLoginConfirmation !== coherentVersioned.value.key
    ) {
      setMutationError(
        reasonError ??
          `Type ${coherentVersioned.value.key} to confirm ${directLoginCommand}.`,
      );
      return;
    }
    const expectedSessionId = sessionId;
    const expectedProviderId = providerId;
    const mutationEpoch = mutationContextRef.current.epoch;
    const command = directLoginCommand;
    const submittingCommand = `${command}-direct-login` as const;
    const mutationToken = Symbol(`platform-provider-${submittingCommand}`);
    mutationLockRef.current = mutationToken;
    setMutationError(null);
    setSubmitting(submittingCommand);
    try {
      const input = { expectedVersion: coherentVersioned.value.version };
      const updated =
        command === "activate"
          ? await api.activatePlatformOidcDirectLogin(
              csrfToken,
              providerId,
              coherentVersioned,
              directLoginReason,
              input,
            )
          : await api.deactivatePlatformOidcDirectLogin(
              csrfToken,
              providerId,
              coherentVersioned,
              directLoginReason,
              input,
            );
      if (
        !mutationIsCurrent(
          mutationEpoch,
          expectedProviderId,
          expectedSessionId,
          mutationToken,
        )
      ) {
        return;
      }
      setState({ kind: "ready", value: updated });
      setDirectLoginCommand(null);
      setDirectLoginReason("");
      setDirectLoginConfirmation("");
      onChanged();
      onNotice({
        message:
          command === "activate"
            ? `${updated.value.displayName} direct platform login is active for pre-linked identities only.`
            : `${updated.value.displayName} direct platform login was deactivated; tenant execution remains active.`,
        tone: "success",
      });
    } catch (caught) {
      if (
        !mutationIsCurrent(
          mutationEpoch,
          expectedProviderId,
          expectedSessionId,
          mutationToken,
        )
      ) {
        return;
      }
      if (
        caught instanceof PhaseTwoApiError &&
        (caught.status === 409 || caught.status === 412)
      ) {
        setDirectLoginCommand(null);
        setDirectLoginReason("");
        setDirectLoginConfirmation("");
      }
      handleMutationFailure(
        caught,
        `Direct platform login was not ${command}d. Review the refreshed provider version and readiness.`,
      );
    } finally {
      releaseMutation(mutationToken, expectedSessionId);
    }
  }

  async function archiveProvider(
    event: React.FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault();
    if (
      !canManage ||
      !providerId ||
      !coherentVersioned ||
      bindingMutationBusy ||
      accountMutationBusy ||
      samlMutationBusy ||
      mutationLockRef.current !== null ||
      coherentVersioned.value.archivedAt !== null ||
      coherentVersioned.value.enabled
    ) {
      return;
    }
    const reasonError = validatePlatformAuthProviderAuditReason(archiveReason);
    if (reasonError || archiveConfirmation !== coherentVersioned.value.key) {
      setMutationError(
        reasonError ??
          `Type ${coherentVersioned.value.key} to confirm archival.`,
      );
      return;
    }
    const expectedSessionId = sessionId;
    const expectedProviderId = providerId;
    const mutationEpoch = mutationContextRef.current.epoch;
    const mutationToken = Symbol("platform-provider-archive");
    mutationLockRef.current = mutationToken;
    const providerName = coherentVersioned.value.displayName;
    setMutationError(null);
    setSubmitting("archive");
    try {
      await api.archivePlatformAuthProvider(
        csrfToken,
        providerId,
        coherentVersioned.etag,
        archiveReason,
        { expectedVersion: coherentVersioned.value.version },
      );
      if (
        !mutationIsCurrent(
          mutationEpoch,
          expectedProviderId,
          expectedSessionId,
          mutationToken,
        )
      ) {
        return;
      }
      setArchiveReason("");
      setArchiveConfirmation("");
      onArchived(providerName);
    } catch (caught) {
      if (
        !mutationIsCurrent(
          mutationEpoch,
          expectedProviderId,
          expectedSessionId,
          mutationToken,
        )
      ) {
        return;
      }
      if (
        caught instanceof PhaseTwoApiError &&
        (caught.status === 409 || caught.status === 412)
      ) {
        setArchiveOpen(false);
        setArchiveReason("");
        setArchiveConfirmation("");
      }
      handleMutationFailure(
        caught,
        "The provider was not archived. Review its current dependencies and version.",
      );
    } finally {
      releaseMutation(mutationToken, expectedSessionId);
    }
  }

  const providerMutationBlocked =
    submitting !== null ||
    bindingMutationBusy ||
    accountMutationBusy ||
    samlMutationBusy;

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (
          !next &&
          (mutationLockRef.current !== null ||
            bindingMutationBusy ||
            accountMutationBusy ||
            samlMutationBusy)
        ) {
          return;
        }
        onOpenChange(next);
      }}
    >
      <DialogContent
        className="platform-idp-detail-dialog"
        showCloseButton={
          submitting === null &&
          !bindingMutationBusy &&
          !accountMutationBusy &&
          !samlMutationBusy
        }
      >
        <DialogHeader>
          <DialogTitle>
            {provider?.displayName ?? "Identity provider"}
          </DialogTitle>
          <DialogDescription>
            Sanitized protocol detail, staged readiness, and audited management
            actions.
          </DialogDescription>
        </DialogHeader>
        {state.kind === "loading" && !provider ? (
          <ProviderDetailSkeleton />
        ) : null}
        {state.kind === "error" ? (
          <div className="platform-idp-load-error">
            <FocusedError message={state.message} />
            <Button
              type="button"
              variant="outline"
              onClick={() => setRefreshRevision((revision) => revision + 1)}
            >
              <RefreshCw aria-hidden="true" /> Reload detail
            </Button>
          </div>
        ) : null}
        {provider && displayVersioned ? (
          <div className="platform-idp-detail-ready">
            {state.kind !== "ready" ? (
              <Alert>
                <ShieldAlert aria-hidden="true" />
                <AlertTitle>
                  Showing a display-only confirmed projection
                </AlertTitle>
                <AlertDescription>
                  Its body and ETag remain paired, but a newer server version is
                  being loaded. All mutations stay locked until refresh
                  completes.
                </AlertDescription>
              </Alert>
            ) : null}
            <ProviderReadinessBand provider={provider} />
            <ProviderFacts provider={provider} etag={displayVersioned.etag} />
            <ProviderConfiguration provider={provider} />
            {coherentVersioned?.value.kind === "saml" ? (
              <PlatformAuthProviderSamlMaterials
                api={api}
                canManage={canManage}
                csrfToken={csrfToken}
                current={{
                  etag: coherentVersioned.etag,
                  value: coherentVersioned.value,
                }}
                onChanged={onChanged}
                onMutationBusyChange={setSamlMutationBusy}
                onNotice={onNotice}
                onPermissionError={onPermissionError}
                onProviderProjectionStale={markProjectionStale}
                onUnauthenticated={onUnauthenticated}
                providerMutationBusy={
                  submitting !== null ||
                  bindingMutationBusy ||
                  accountMutationBusy
                }
                sessionId={sessionId}
              />
            ) : null}
            {coherentVersioned?.value.kind === "ldap" ? (
              <PlatformLdapProviderAdministration
                api={api}
                canManageConfiguration={canManage}
                canManagePolicy={canManagePolicy}
                canTest={canTest}
                csrfToken={csrfToken}
                current={{
                  etag: coherentVersioned.etag,
                  value: coherentVersioned.value,
                }}
                onChanged={onChanged}
                onMutationBusyChange={setSamlMutationBusy}
                onNotice={onNotice}
                onPermissionError={onPermissionError}
                onProviderProjectionStale={markProjectionStale}
                onUnauthenticated={onUnauthenticated}
                providerMutationBusy={
                  submitting !== null ||
                  bindingMutationBusy ||
                  accountMutationBusy
                }
                sessionId={sessionId}
              />
            ) : null}
            {provider.kind !== "ldap" ? (
              <PlatformAuthProviderTenantBindings
                api={api}
                canManage={canManageBindings}
                canRead={canReadBindings}
                csrfToken={csrfToken}
                onMutationBusyChange={setBindingMutationBusy}
                onNotice={onNotice}
                onPermissionError={onPermissionError}
                onProviderProjectionStale={markProjectionStale}
                onUnauthenticated={onUnauthenticated}
                providerArchived={
                  provider.archivedAt !== null ||
                  coherentVersioned === undefined
                }
                {...(coherentVersioned
                  ? {
                      providerAccountMode: provider.accountMode,
                      providerEnabled: provider.enabled,
                      providerKind: provider.kind,
                    }
                  : {})}
                providerMutationBusy={
                  submitting !== null || accountMutationBusy || samlMutationBusy
                }
                providerId={provider.id}
                refreshRevision={bindingRefreshRevision}
                sessionId={sessionId}
              />
            ) : null}

            {provider.kind !== "ldap" ? (
              <PlatformAuthProviderAccounts
                api={api}
                canManage={canManageAccounts}
                canRead={canReadAccounts}
                csrfToken={csrfToken}
                onMutationBusyChange={setAccountMutationBusy}
                onNotice={onNotice}
                onPermissionError={onPermissionError}
                onUnauthenticated={onUnauthenticated}
                {...(provider.kind === "oidc" &&
                provider.configured &&
                provider.archivedAt === null
                  ? { prelinkIssuer: provider.configuration.issuer }
                  : {})}
                providerId={provider.id}
                providerMutationBusy={
                  submitting !== null ||
                  bindingMutationBusy ||
                  samlMutationBusy ||
                  coherentVersioned === undefined
                }
                providerVersion={provider.version}
                sessionId={sessionId}
              />
            ) : null}

            {coherentVersioned &&
            canManage &&
            provider.kind !== "ldap" &&
            provider.archivedAt === null ? (
              <section
                className="platform-idp-actions"
                aria-labelledby="platform-idp-actions-title"
              >
                <div className="platform-idp-section-heading">
                  <div>
                    <p className="section-label">Version-bound commands</p>
                    <h3 id="platform-idp-actions-title">Provider actions</h3>
                  </div>
                  <Badge variant="outline">
                    If-Match {coherentVersioned.etag}
                  </Badge>
                </div>
                <div className="platform-idp-action-buttons">
                  <Button
                    type="button"
                    variant="outline"
                    disabled={providerMutationBlocked}
                    onClick={() => {
                      setSecretOpen(false);
                      setClientSecret("");
                      setSecretReason("");
                      setArchiveOpen(false);
                      setArchiveReason("");
                      setArchiveConfirmation("");
                      setLifecycleCommand(null);
                      setLifecycleReason("");
                      setLifecycleConfirmation("");
                      setDirectLoginCommand(null);
                      setDirectLoginReason("");
                      setDirectLoginConfirmation("");
                      setMetadataDraft(metadataDraftFromProvider(provider));
                      setMetadataErrors([]);
                      setMetadataConflict(false);
                      setMutationError(null);
                    }}
                  >
                    <Save aria-hidden="true" /> Edit metadata
                  </Button>
                  {provider.kind === "oidc" ? (
                    <Button
                      type="button"
                      variant="outline"
                      disabled={providerMutationBlocked}
                      onClick={() => {
                        setMetadataDraft(null);
                        setMetadataErrors([]);
                        setMetadataConflict(false);
                        setArchiveOpen(false);
                        setArchiveReason("");
                        setArchiveConfirmation("");
                        setLifecycleCommand(null);
                        setLifecycleReason("");
                        setLifecycleConfirmation("");
                        setDirectLoginCommand(null);
                        setDirectLoginReason("");
                        setDirectLoginConfirmation("");
                        setSecretOpen(true);
                        setMutationError(null);
                      }}
                    >
                      <KeyRound aria-hidden="true" />
                      {provider.configuration.clientSecretPresent
                        ? "Replace client secret"
                        : "Set client secret"}
                    </Button>
                  ) : null}
                  {provider.enabled || provider.activationAvailable ? (
                    <Button
                      type="button"
                      variant={provider.enabled ? "destructive" : "default"}
                      disabled={
                        providerMutationBlocked ||
                        (provider.enabled && provider.platformLoginEnabled)
                      }
                      onClick={() => {
                        setMetadataDraft(null);
                        setMetadataErrors([]);
                        setMetadataConflict(false);
                        setSecretOpen(false);
                        setClientSecret("");
                        setSecretReason("");
                        setArchiveOpen(false);
                        setArchiveReason("");
                        setArchiveConfirmation("");
                        setLifecycleCommand(
                          provider.enabled ? "deactivate" : "activate",
                        );
                        setLifecycleReason("");
                        setLifecycleConfirmation("");
                        setDirectLoginCommand(null);
                        setDirectLoginReason("");
                        setDirectLoginConfirmation("");
                        setAccountMode("existing_identity");
                        setMutationError(null);
                      }}
                    >
                      {provider.enabled
                        ? "Deactivate tenant execution"
                        : "Activate tenant execution"}
                    </Button>
                  ) : null}
                  {provider.enabled ? (
                    <Button
                      type="button"
                      variant={
                        provider.platformLoginEnabled
                          ? "destructive"
                          : "default"
                      }
                      disabled={
                        providerMutationBlocked ||
                        (!provider.platformLoginEnabled &&
                          !provider.platformLoginActivationAvailable)
                      }
                      onClick={() => {
                        setMetadataDraft(null);
                        setMetadataErrors([]);
                        setMetadataConflict(false);
                        setSecretOpen(false);
                        setClientSecret("");
                        setSecretReason("");
                        setArchiveOpen(false);
                        setArchiveReason("");
                        setArchiveConfirmation("");
                        setLifecycleCommand(null);
                        setLifecycleReason("");
                        setLifecycleConfirmation("");
                        setDirectLoginCommand(
                          provider.platformLoginEnabled
                            ? "deactivate"
                            : "activate",
                        );
                        setDirectLoginReason("");
                        setDirectLoginConfirmation("");
                        setMutationError(null);
                      }}
                    >
                      {provider.platformLoginEnabled
                        ? "Deactivate direct platform login"
                        : provider.platformLoginActivationAvailable
                          ? "Activate direct platform login"
                          : "Direct platform login unavailable"}
                    </Button>
                  ) : null}
                  {!provider.enabled ? (
                    <Button
                      type="button"
                      variant="destructive"
                      disabled={providerMutationBlocked}
                      onClick={() => {
                        setMetadataDraft(null);
                        setMetadataErrors([]);
                        setMetadataConflict(false);
                        setSecretOpen(false);
                        setClientSecret("");
                        setSecretReason("");
                        setLifecycleCommand(null);
                        setLifecycleReason("");
                        setLifecycleConfirmation("");
                        setDirectLoginCommand(null);
                        setDirectLoginReason("");
                        setDirectLoginConfirmation("");
                        setArchiveOpen(true);
                        setMutationError(null);
                      }}
                    >
                      <Archive aria-hidden="true" /> Archive provider
                    </Button>
                  ) : null}
                </div>

                {metadataDraft ? (
                  <form
                    className="platform-idp-action-form"
                    aria-label="Edit provider metadata"
                    aria-busy={submitting === "metadata"}
                    onSubmit={(event) => void updateMetadata(event)}
                  >
                    <h4>Replace metadata</h4>
                    <MetadataFields
                      disabled={providerMutationBlocked}
                      draft={metadataDraft}
                      keyReadOnly
                      onChange={(patch) =>
                        setMetadataDraft({ ...metadataDraft, ...patch })
                      }
                      prefix="platform-idp-edit"
                    />
                    <AuditReasonField
                      disabled={providerMutationBlocked}
                      id="platform-idp-edit-reason"
                      value={metadataDraft.auditReason}
                      onChange={(auditReason) =>
                        setMetadataDraft({ ...metadataDraft, auditReason })
                      }
                    />
                    {metadataErrors.length > 0 ? (
                      <ValidationSummary errors={metadataErrors} />
                    ) : null}
                    {metadataConflict ? (
                      <Alert variant="destructive">
                        <ShieldAlert aria-hidden="true" />
                        <AlertTitle>Provider changed on the server</AlertTitle>
                        <AlertDescription>
                          This draft was not retried. Close it and start again
                          from the refreshed version.
                        </AlertDescription>
                      </Alert>
                    ) : null}
                    <div className="platform-idp-form-actions">
                      <Button
                        type="button"
                        variant="ghost"
                        disabled={providerMutationBlocked}
                        onClick={() => {
                          setMetadataDraft(null);
                          setMetadataConflict(false);
                          setMutationError(null);
                        }}
                      >
                        Cancel edit
                      </Button>
                      <Button
                        type="submit"
                        disabled={providerMutationBlocked || metadataConflict}
                      >
                        <Save aria-hidden="true" />
                        {submitting === "metadata"
                          ? "Saving…"
                          : "Replace metadata"}
                      </Button>
                    </div>
                  </form>
                ) : null}

                {secretOpen && provider.kind === "oidc" ? (
                  <form
                    className="platform-idp-action-form platform-idp-secret-form"
                    aria-label="Replace OIDC client secret"
                    aria-busy={submitting === "secret"}
                    onSubmit={(event) => void replaceClientSecret(event)}
                  >
                    <div>
                      <h4>Write-only OIDC client secret</h4>
                      <p>
                        The value is submitted once, never read back, and
                        cleared from this form after every attempt.
                      </p>
                    </div>
                    <TextInputField
                      autoComplete="new-password"
                      disabled={providerMutationBlocked}
                      id="platform-idp-client-secret"
                      label="Client secret"
                      type="password"
                      value={clientSecret}
                      onChange={setClientSecret}
                    />
                    <AuditReasonField
                      disabled={providerMutationBlocked}
                      id="platform-idp-secret-reason"
                      value={secretReason}
                      onChange={setSecretReason}
                    />
                    <div className="platform-idp-form-actions">
                      <Button
                        type="button"
                        variant="ghost"
                        disabled={providerMutationBlocked}
                        onClick={() => {
                          setSecretOpen(false);
                          setClientSecret("");
                          setSecretReason("");
                          setMutationError(null);
                        }}
                      >
                        Cancel secret change
                      </Button>
                      <Button type="submit" disabled={providerMutationBlocked}>
                        <LockKeyhole aria-hidden="true" />
                        {submitting === "secret"
                          ? "Submitting…"
                          : "Store write-only secret"}
                      </Button>
                    </div>
                  </form>
                ) : null}

                {lifecycleCommand ? (
                  <form
                    className="platform-idp-action-form"
                    aria-label={`${lifecycleCommand === "activate" ? "Activate" : "Deactivate"} provider tenant execution`}
                    aria-busy={submitting === lifecycleCommand}
                    onSubmit={(event) => void changeProviderExecution(event)}
                  >
                    <div>
                      <h4>
                        {lifecycleCommand === "activate"
                          ? `Activate ${kindLabel(provider.kind)} tenant execution`
                          : `Deactivate ${kindLabel(provider.kind)} tenant execution`}
                      </h4>
                      <p>
                        This changes tenant-bound authentication only. It cannot
                        enable direct platform login or create platform roles.
                      </p>
                    </div>
                    {lifecycleCommand === "activate" ? (
                      <SelectField
                        disabled={providerMutationBlocked}
                        id="platform-idp-account-mode"
                        label="External identity account mode"
                        value={accountMode}
                        options={[
                          ["existing_identity", "Match an existing identity"],
                          [
                            "create",
                            "Create an identity without platform authority",
                          ],
                        ]}
                        onChange={setAccountMode}
                      />
                    ) : null}
                    <AuditReasonField
                      disabled={providerMutationBlocked}
                      id="platform-idp-lifecycle-reason"
                      value={lifecycleReason}
                      onChange={setLifecycleReason}
                    />
                    <TextInputField
                      disabled={providerMutationBlocked}
                      id="platform-idp-lifecycle-confirmation"
                      label={`Type ${provider.key} to confirm`}
                      value={lifecycleConfirmation}
                      onChange={setLifecycleConfirmation}
                    />
                    <div className="platform-idp-form-actions">
                      <Button
                        type="button"
                        variant="ghost"
                        disabled={providerMutationBlocked}
                        onClick={() => {
                          setLifecycleCommand(null);
                          setLifecycleReason("");
                          setLifecycleConfirmation("");
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
                        disabled={providerMutationBlocked}
                      >
                        {submitting === lifecycleCommand
                          ? "Submitting…"
                          : lifecycleCommand === "activate"
                            ? "Activate tenant execution"
                            : "Deactivate tenant execution"}
                      </Button>
                    </div>
                  </form>
                ) : null}

                {directLoginCommand ? (
                  <form
                    className="platform-idp-action-form"
                    aria-label={`${directLoginCommand === "activate" ? "Activate" : "Deactivate"} direct platform login`}
                    aria-busy={
                      submitting === `${directLoginCommand}-direct-login`
                    }
                    onSubmit={(event) => void changeDirectLogin(event)}
                  >
                    <div>
                      <h4>
                        {directLoginCommand === "activate"
                          ? `Activate direct ${kindLabel(provider.kind)} platform login`
                          : `Deactivate direct ${kindLabel(provider.kind)} platform login`}
                      </h4>
                      <p>
                        {directLoginCommand === "activate" &&
                        !provider.platformLoginActivationAvailable
                          ? `Activation prerequisites changed on the server. Refresh the provider after restoring its live ${kindLabel(provider.kind)} runtime, protected material, trust pins, keyring, and platform-floor dependencies.`
                          : "This is a separate platform-wide login boundary. It admits pre-linked identities only: provider claims cannot create users, platform roles, or tenant access."}
                      </p>
                    </div>
                    <div className="platform-idp-readonly-policy">
                      <LockKeyhole aria-hidden="true" />
                      <span>
                        <strong>Account mode: existing identity</strong>
                        <small>
                          Pre-link the external subject to an existing platform
                          account before activation. This mode cannot be changed
                          by this command.
                        </small>
                      </span>
                    </div>
                    <AuditReasonField
                      disabled={providerMutationBlocked}
                      id="platform-idp-direct-login-reason"
                      value={directLoginReason}
                      onChange={setDirectLoginReason}
                    />
                    <TextInputField
                      disabled={providerMutationBlocked}
                      id="platform-idp-direct-login-confirmation"
                      label={`Type ${provider.key} to confirm`}
                      value={directLoginConfirmation}
                      onChange={setDirectLoginConfirmation}
                    />
                    <div className="platform-idp-form-actions">
                      <Button
                        type="button"
                        variant="ghost"
                        disabled={providerMutationBlocked}
                        onClick={() => {
                          setDirectLoginCommand(null);
                          setDirectLoginReason("");
                          setDirectLoginConfirmation("");
                          setMutationError(null);
                        }}
                      >
                        Cancel {directLoginCommand}
                      </Button>
                      <Button
                        type="submit"
                        variant={
                          directLoginCommand === "deactivate"
                            ? "destructive"
                            : "default"
                        }
                        disabled={
                          providerMutationBlocked ||
                          (directLoginCommand === "activate" &&
                            !provider.platformLoginActivationAvailable)
                        }
                      >
                        {submitting === `${directLoginCommand}-direct-login`
                          ? "Submitting…"
                          : directLoginCommand === "activate"
                            ? "Activate direct platform login"
                            : "Deactivate direct platform login"}
                      </Button>
                    </div>
                  </form>
                ) : null}

                {archiveOpen ? (
                  <form
                    className="platform-idp-action-form platform-idp-archive-form"
                    aria-label="Archive provider"
                    aria-busy={submitting === "archive"}
                    onSubmit={(event) => void archiveProvider(event)}
                  >
                    <div>
                      <h4>Archive provider permanently</h4>
                      <p>
                        This API cannot unarchive or purge the provider. Type
                        the stable key to confirm.
                      </p>
                    </div>
                    <AuditReasonField
                      disabled={providerMutationBlocked}
                      id="platform-idp-archive-reason"
                      value={archiveReason}
                      onChange={setArchiveReason}
                    />
                    <TextInputField
                      disabled={providerMutationBlocked}
                      id="platform-idp-archive-confirmation"
                      label={`Type ${provider.key} to confirm`}
                      value={archiveConfirmation}
                      onChange={setArchiveConfirmation}
                    />
                    <div className="platform-idp-form-actions">
                      <Button
                        type="button"
                        variant="ghost"
                        disabled={providerMutationBlocked}
                        onClick={() => {
                          setArchiveOpen(false);
                          setArchiveReason("");
                          setArchiveConfirmation("");
                          setMutationError(null);
                        }}
                      >
                        Cancel archival
                      </Button>
                      <Button
                        type="submit"
                        variant="destructive"
                        disabled={providerMutationBlocked}
                      >
                        <Archive aria-hidden="true" />
                        {submitting === "archive"
                          ? "Archiving…"
                          : "Archive provider"}
                      </Button>
                    </div>
                  </form>
                ) : null}
                {mutationError ? (
                  <FocusedError message={mutationError} />
                ) : null}
              </section>
            ) : null}
          </div>
        ) : null}
      </DialogContent>
    </Dialog>
  );
}

function ProviderReadinessBand({
  provider,
}: {
  provider?: PlatformAuthProviderView;
}): React.JSX.Element {
  if (provider?.kind === "ldap") {
    return (
      <section
        className="platform-idp-readiness"
        aria-label="Platform LDAP readiness"
      >
        <div className="platform-idp-readiness__intro">
          <Network aria-hidden="true" />
          <span>
            <small>Directory readiness</small>
            <strong>{provider.displayName}</strong>
          </span>
        </div>
        <div className="platform-idp-readiness__gate" data-state="ready">
          <ShieldCheck aria-hidden="true" />
          <span>
            <small>Tenant execution</small>
            <strong>Not applicable</strong>
          </span>
        </div>
        <div
          className="platform-idp-readiness__gate"
          data-state={
            provider.platformLoginEnabled
              ? "ready"
              : provider.platformLoginActivationAvailable
                ? "pending"
                : "blocked"
          }
        >
          {provider.platformLoginEnabled ? (
            <ShieldCheck aria-hidden="true" />
          ) : provider.platformLoginActivationAvailable ? (
            <ShieldAlert aria-hidden="true" />
          ) : (
            <CircleSlash2 aria-hidden="true" />
          )}
          <span>
            <small>Tenantless platform login</small>
            <strong>
              {provider.platformLoginEnabled
                ? "Active · existing identity + TOTP"
                : provider.platformLoginActivationAvailable
                  ? "Ready to activate"
                  : "Blocked by readiness"}
            </strong>
          </span>
        </div>
        <div className="platform-idp-readiness__gate" data-state="pending">
          <ShieldAlert aria-hidden="true" />
          <span>
            <small>Session provenance</small>
            <strong>Revalidated on authority drift</strong>
          </span>
        </div>
      </section>
    );
  }
  return (
    <section
      className="platform-idp-readiness"
      aria-label="Platform federation readiness"
    >
      <div className="platform-idp-readiness__intro">
        <Fingerprint aria-hidden="true" />
        <span>
          <small>Federation readiness</small>
          <strong>
            {provider ? provider.displayName : "Global staging boundary"}
          </strong>
        </span>
      </div>
      <div
        className="platform-idp-readiness__gate"
        data-state={
          provider?.enabled
            ? "ready"
            : provider?.activationAvailable
              ? "pending"
              : "blocked"
        }
      >
        {provider?.enabled ? (
          <ShieldCheck aria-hidden="true" />
        ) : provider?.activationAvailable ? (
          <ShieldAlert aria-hidden="true" />
        ) : (
          <CircleSlash2 aria-hidden="true" />
        )}
        <span>
          <small>Tenant execution</small>
          <strong>
            {provider?.enabled
              ? "Active"
              : provider?.activationAvailable
                ? "Ready to activate"
                : "Blocked"}
          </strong>
        </span>
      </div>
      <div
        className="platform-idp-readiness__gate"
        data-state={
          provider?.platformLoginEnabled
            ? "ready"
            : provider?.platformLoginActivationAvailable
              ? "pending"
              : "blocked"
        }
      >
        {provider?.platformLoginEnabled ? (
          <ShieldCheck aria-hidden="true" />
        ) : provider?.platformLoginActivationAvailable ? (
          <ShieldAlert aria-hidden="true" />
        ) : (
          <CircleSlash2 aria-hidden="true" />
        )}
        <span>
          <small>Platform login</small>
          <strong>
            {provider?.platformLoginEnabled
              ? "Active · pre-linked identities"
              : provider?.platformLoginActivationAvailable
                ? "Ready to activate"
                : provider?.kind === "oidc" &&
                    provider.configuration.useUserInfo
                  ? "Blocked · UserInfo is tenant-only"
                  : "Blocked"}
          </strong>
        </span>
      </div>
      <div className="platform-idp-readiness__gate" data-state="pending">
        <ShieldAlert aria-hidden="true" />
        <span>
          <small>Binding + provenance</small>
          <strong>Evaluated per tenant</strong>
        </span>
      </div>
    </section>
  );
}

function ProviderFacts({
  etag,
  provider,
}: {
  etag: string;
  provider: PlatformAuthProviderView;
}): React.JSX.Element {
  return (
    <section
      className="platform-idp-facts"
      aria-labelledby="platform-idp-facts-title"
    >
      <div className="platform-idp-section-heading">
        <div>
          <p className="section-label">Sanitized representation</p>
          <h3 id="platform-idp-facts-title">Provider facts</h3>
        </div>
        <ProviderStateBadge provider={provider} />
      </div>
      <dl>
        <Fact label="Protocol" value={kindLabel(provider.kind)} />
        <Fact label="Stable key" value={provider.key} code />
        <Fact label="Resource version" value={String(provider.version)} code />
        <Fact label="Strong ETag" value={etag} code />
        <Fact
          label="Account mode"
          value={humanizeToken(provider.accountMode)}
        />
        <Fact
          label="Configuration"
          value={provider.configured ? "Recorded" : "Incomplete"}
        />
        <Fact
          label="Direct platform login"
          value={provider.platformLoginEnabled ? "Active" : "Disabled"}
        />
        <Fact
          label="Archived"
          value={provider.archivedAt === null ? "No" : provider.archivedAt}
        />
        <Fact label="Updated" value={provider.updatedAt} />
      </dl>
      {provider.description ? <p>{provider.description}</p> : null}
    </section>
  );
}

function ProviderConfiguration({
  provider,
}: {
  provider: PlatformAuthProviderView;
}): React.JSX.Element {
  if (provider.kind === "oidc") {
    const configuration = provider.configuration;
    return (
      <section
        className="platform-idp-configuration"
        aria-labelledby="platform-idp-configuration-title"
      >
        <div className="platform-idp-section-heading">
          <div>
            <p className="section-label">OIDC safe detail</p>
            <h3 id="platform-idp-configuration-title">Discovery coordinates</h3>
          </div>
          <Badge variant="outline">
            Client secret{" "}
            {configuration.clientSecretPresent ? "present" : "not set"}
          </Badge>
        </div>
        <DeploymentManagedEndpointNotice />
        <dl>
          <Fact label="Issuer" value={configuration.issuer} code />
          <Fact label="Client ID" value={configuration.clientId} code />
          <Fact
            label="Platform callback (deployment-managed)"
            value={configuration.redirectUri}
            code
          />
          <Fact
            label="Tenant callback (deployment-managed)"
            value={configuration.tenantRedirectUri}
            code
          />
          <Fact
            label="Post-logout URI (deployment-managed)"
            value={configuration.postLogoutRedirectUri}
            code
          />
          <Fact
            label="Additional scopes"
            value={configuration.extraScopes.join(" ") || "None"}
          />
          <Fact
            label="Refresh token allowed"
            value={configuration.allowRefreshToken ? "Yes" : "No"}
          />
          <Fact
            label="UserInfo enabled"
            value={configuration.useUserInfo ? "Yes" : "No"}
          />
          <Fact
            label="Safe revisions"
            value={`config ${provider.configurationRevision} · security ${provider.securityRevision} · secret ${configuration.clientSecretRevision} · discovery ${configuration.discoveryRevision} · JWKS ${configuration.jwksRevision}`}
            code
          />
        </dl>
      </section>
    );
  }

  if (provider.kind === "ldap") {
    const configuration = provider.configuration;
    return (
      <section
        className="platform-idp-configuration"
        aria-labelledby="platform-idp-configuration-title"
      >
        <div className="platform-idp-section-heading">
          <div>
            <p className="section-label">LDAP safe detail</p>
            <h3 id="platform-idp-configuration-title">Directory coordinates</h3>
          </div>
          <Badge variant="outline">
            Bind secret {provider.secretPresent ? "present" : "not set"}
          </Badge>
        </div>
        <dl>
          <Fact
            label="Template"
            value={humanizeToken(configuration.template)}
          />
          <Fact label="Bind DN" value={configuration.bindDn} code />
          <Fact label="User base DN" value={configuration.userBaseDn} code />
          <Fact
            label="User search filter"
            value={configuration.userSearchFilter}
            code
          />
          <Fact
            label="Immutable subject"
            value={`${configuration.immutableSubjectAttribute} · ${humanizeToken(configuration.immutableSubjectFormat)}`}
          />
          <Fact
            label="Account admission"
            value="Existing active identity + local TOTP"
          />
          <Fact
            label="Directory limits"
            value={`${configuration.maxEntries} entries · ${configuration.maxPages} pages · ${configuration.maxGroups} groups`}
          />
          <Fact
            label="Configured endpoints"
            value={`${provider.endpoints.filter((endpoint) => endpoint.enabled).length} enabled of ${provider.endpoints.length}`}
          />
          <Fact
            label="Role mappings"
            value={`${provider.mappings.filter((mapping) => mapping.enabled && mapping.archivedAt === null).length} enabled of ${provider.mappings.length}`}
          />
          <Fact
            label="Safe revisions"
            value={`config ${provider.configurationRevision} · security ${provider.securityRevision} · plan ${provider.planRevision}`}
            code
          />
        </dl>
      </section>
    );
  }

  const configuration = provider.configuration;
  return (
    <section
      className="platform-idp-configuration"
      aria-labelledby="platform-idp-configuration-title"
    >
      <div className="platform-idp-section-heading">
        <div>
          <p className="section-label">SAML safe detail</p>
          <h3 id="platform-idp-configuration-title">Trust coordinates</h3>
        </div>
        <Badge variant="outline">
          SP key {configuration.spKeyPresent ? "present" : "not set"}
        </Badge>
      </div>
      <DeploymentManagedEndpointNotice />
      <dl>
        <Fact
          label="Expected IdP entity ID"
          value={configuration.expectedEntityId}
          code
        />
        <Fact
          label="SP entity ID (deployment-managed)"
          value={configuration.spEntityId}
          code
        />
        <Fact
          label="ACS URL (deployment-managed)"
          value={configuration.acsUrl}
          code
        />
        <Fact
          label="Signature policy"
          value={humanizeToken(configuration.signaturePolicy)}
        />
        <Fact
          label="Encryption policy"
          value={humanizeToken(configuration.encryptionPolicy)}
        />
        <Fact
          label="Subject source"
          value={humanizeToken(configuration.subjectSource)}
        />
        {configuration.subjectSource === "immutable_attribute" ? (
          <>
            <Fact
              label="Subject attribute"
              value={configuration.subjectAttributeName ?? "Unavailable"}
              code
            />
            <Fact
              label="Attribute format"
              value={configuration.subjectAttributeNameFormat ?? "Unavailable"}
              code
            />
          </>
        ) : null}
        <Fact
          label="Requested AuthnContexts"
          value={configuration.requestedAuthnContexts.join(" · ")}
        />
        <Fact
          label="Timing"
          value={`${configuration.clockSkewNanoseconds / 1_000_000_000}s skew · ${configuration.maxAuthenticationAgeNanoseconds / 1_000_000_000}s max age`}
        />
        <Fact
          label="Safe revisions"
          value={`config ${provider.configurationRevision} · security ${provider.securityRevision} · SP key ${configuration.spKeyRevision} · metadata ${configuration.metadataRevision}`}
          code
        />
      </dl>
    </section>
  );
}

function MetadataFields({
  disabled = false,
  draft,
  keyReadOnly = false,
  onChange,
  prefix,
}: {
  disabled?: boolean;
  draft: Pick<
    PlatformAuthProviderMetadataDraft,
    "description" | "displayName" | "key"
  >;
  onChange: (
    patch: Partial<
      Pick<
        PlatformAuthProviderMetadataDraft,
        "description" | "displayName" | "key"
      >
    >,
  ) => void;
  keyReadOnly?: boolean;
  prefix: string;
}): React.JSX.Element {
  return (
    <div className="platform-idp-form-grid">
      <TextInputField
        disabled={disabled}
        hint={
          keyReadOnly
            ? "Immutable public locator. It remains in replacement requests to bind the command to this provider."
            : "Choose carefully: this public locator becomes immutable after creation."
        }
        id={`${prefix}-key`}
        label="Stable key"
        readOnly={keyReadOnly}
        value={draft.key}
        onChange={(key) => onChange({ key: key.toLowerCase() })}
      />
      <TextInputField
        disabled={disabled}
        id={`${prefix}-display-name`}
        label="Display name"
        value={draft.displayName}
        onChange={(displayName) => onChange({ displayName })}
      />
      <TextareaField
        className="platform-idp-form-grid__wide"
        disabled={disabled}
        id={`${prefix}-description`}
        label="Description"
        optional
        value={draft.description}
        onChange={(description) => onChange({ description })}
      />
    </div>
  );
}

function DeploymentManagedEndpointNotice(): React.JSX.Element {
  return (
    <div className="platform-idp-readonly-policy">
      <LockKeyhole aria-hidden="true" />
      <span>
        <strong>Deployment-managed registration values</strong>
        <small>
          Periapsis derives these values from this app&apos;s public origin.
          Copy them exactly into the upstream provider; they cannot be edited
          here.
        </small>
      </span>
    </div>
  );
}

function DeploymentEndpointField({
  hint,
  id,
  label,
  value,
}: {
  hint: string;
  id: string;
  label: string;
  value: string;
}): React.JSX.Element {
  return (
    <FormField htmlFor={id} hint={hint} label={label}>
      <Input
        aria-describedby={`${id}-hint`}
        id={id}
        readOnly
        type="url"
        value={value}
      />
    </FormField>
  );
}

function OidcCreateFields({
  deploymentEndpoints,
  draft,
  onChange,
}: {
  deploymentEndpoints: PlatformAuthProviderDeploymentEndpoints | null;
  draft: Extract<PlatformAuthProviderDraft, { kind: "oidc" }>;
  onChange: (
    draft: Extract<PlatformAuthProviderDraft, { kind: "oidc" }>,
  ) => void;
}): React.JSX.Element {
  return (
    <fieldset className="platform-idp-protocol-fields">
      <legend>OIDC configuration</legend>
      <DeploymentManagedEndpointNotice />
      <div className="platform-idp-form-grid">
        <TextInputField
          id="platform-idp-oidc-issuer"
          label="Issuer"
          type="url"
          value={draft.issuer}
          onChange={(issuer) => onChange({ ...draft, issuer })}
        />
        <TextInputField
          id="platform-idp-oidc-client-id"
          label="Client ID"
          value={draft.clientId}
          onChange={(clientId) => onChange({ ...draft, clientId })}
        />
        <DeploymentEndpointField
          id="platform-idp-oidc-redirect-uri"
          label="Platform redirect URI"
          hint="Register this exact callback before direct platform login is explicitly activated."
          value={deploymentEndpoints?.oidcRedirectUri ?? ""}
        />
        <DeploymentEndpointField
          id="platform-idp-oidc-tenant-redirect-uri"
          label="Tenant redirect URI"
          hint="Register this exact callback for tenant-bound OIDC authentication."
          value={deploymentEndpoints?.oidcTenantRedirectUri ?? ""}
        />
        <DeploymentEndpointField
          id="platform-idp-oidc-post-logout-uri"
          label="Post-logout redirect URI"
          hint="Register this exact return URI if the provider supports RP-initiated logout."
          value={deploymentEndpoints?.oidcPostLogoutRedirectUri ?? ""}
        />
        <TextInputField
          className="platform-idp-form-grid__wide"
          hint="Space-separated additions only. openid and refresh-related offline_access are managed automatically."
          id="platform-idp-oidc-scopes"
          label="Additional scopes"
          optional
          value={draft.extraScopes}
          onChange={(extraScopes) => onChange({ ...draft, extraScopes })}
        />
      </div>
      <div className="platform-idp-boolean-grid">
        <BooleanField
          checked={draft.allowRefreshToken}
          id="platform-idp-oidc-refresh-token"
          label="Allow refresh-token handling later"
          hint="Adds offline_access to request the bounded encrypted refresh lifecycle; activation remains separate."
          onChange={(allowRefreshToken) =>
            onChange(withPlatformOidcRefreshToken(draft, allowRefreshToken))
          }
        />
        <BooleanField
          checked={draft.useUserInfo}
          id="platform-idp-oidc-user-info"
          label="Use the UserInfo endpoint"
          hint="Used only when tenant execution is explicitly activated."
          onChange={(useUserInfo) => onChange({ ...draft, useUserInfo })}
        />
      </div>
      <div className="platform-idp-readonly-policy">
        <LockKeyhole aria-hidden="true" />
        <span>
          <strong>Client secret intentionally absent</strong>
          <small>
            Set it through the dedicated write-only action after creation.
          </small>
        </span>
      </div>
    </fieldset>
  );
}

function SamlCreateFields({
  deploymentEndpoints,
  draft,
  onChange,
}: {
  deploymentEndpoints: PlatformAuthProviderDeploymentEndpoints | null;
  draft: Extract<PlatformAuthProviderDraft, { kind: "saml" }>;
  onChange: (
    draft: Extract<PlatformAuthProviderDraft, { kind: "saml" }>,
  ) => void;
}): React.JSX.Element {
  return (
    <fieldset className="platform-idp-protocol-fields">
      <legend>SAML configuration</legend>
      <DeploymentManagedEndpointNotice />
      <div className="platform-idp-form-grid">
        <TextInputField
          id="platform-idp-saml-entity-id"
          label="Expected IdP entity ID"
          value={draft.expectedEntityId}
          onChange={(expectedEntityId) =>
            onChange({ ...draft, expectedEntityId })
          }
        />
        <DeploymentEndpointField
          id="platform-idp-saml-sp-entity-id"
          label="SP entity ID"
          hint="Use this exact service-provider entity and metadata URI at the IdP."
          value={deploymentEndpoints?.samlSpEntityId ?? ""}
        />
        <DeploymentEndpointField
          id="platform-idp-saml-acs-url"
          label="ACS URL"
          hint="Register this exact assertion consumer service URL at the IdP."
          value={deploymentEndpoints?.samlAcsUrl ?? ""}
        />
        <SelectField
          id="platform-idp-saml-signature-algorithm"
          label="Redirect signature algorithm"
          options={platformSamlSignatureAlgorithms.map((option) => [
            option.value,
            option.label,
          ])}
          value={draft.redirectSignatureAlgorithm}
          onChange={(
            redirectSignatureAlgorithm: PlatformSamlSignatureAlgorithm,
          ) => onChange({ ...draft, redirectSignatureAlgorithm })}
        />
        <SelectField
          id="platform-idp-saml-signature-policy"
          label="Signature policy"
          options={
            [
              ["signed_assertion", "Signed assertion"],
              ["signed_response", "Signed response"],
              ["both", "Signed response and assertion"],
            ] as const
          }
          value={draft.signaturePolicy}
          onChange={(signaturePolicy: PlatformSamlSignaturePolicy) =>
            onChange({ ...draft, signaturePolicy })
          }
        />
        <SelectField
          id="platform-idp-saml-subject-source"
          label="Immutable subject source"
          options={
            [
              ["persistent_nameid", "Persistent NameID"],
              ["immutable_attribute", "Immutable attribute"],
            ] as const
          }
          value={draft.subjectSource}
          onChange={(subjectSource: PlatformSamlSubjectSource) =>
            onChange({
              ...draft,
              subjectAttributeName:
                subjectSource === "persistent_nameid"
                  ? ""
                  : draft.subjectAttributeName,
              subjectAttributeNameFormat:
                subjectSource === "persistent_nameid"
                  ? ""
                  : draft.subjectAttributeNameFormat,
              subjectSource,
            })
          }
        />
        {draft.subjectSource === "immutable_attribute" ? (
          <>
            <TextInputField
              id="platform-idp-saml-subject-attribute"
              label="Subject attribute name"
              value={draft.subjectAttributeName}
              onChange={(subjectAttributeName) =>
                onChange({ ...draft, subjectAttributeName })
              }
            />
            <TextInputField
              id="platform-idp-saml-subject-format"
              label="Subject attribute name format"
              value={draft.subjectAttributeNameFormat}
              onChange={(subjectAttributeNameFormat) =>
                onChange({ ...draft, subjectAttributeNameFormat })
              }
            />
          </>
        ) : null}
        <TextareaField
          className="platform-idp-form-grid__wide"
          hint="Enter one absolute AuthnContext URI per line."
          id="platform-idp-saml-contexts"
          label="Requested AuthnContexts"
          value={draft.requestedAuthnContexts}
          onChange={(requestedAuthnContexts) =>
            onChange({ ...draft, requestedAuthnContexts })
          }
        />
        <TextInputField
          id="platform-idp-saml-clock-skew"
          label="Clock skew (seconds)"
          type="number"
          value={draft.clockSkewSeconds}
          onChange={(clockSkewSeconds) =>
            onChange({ ...draft, clockSkewSeconds })
          }
        />
        <TextInputField
          id="platform-idp-saml-max-age"
          label="Maximum authentication age (seconds)"
          type="number"
          value={draft.maxAuthenticationAgeSeconds}
          onChange={(maxAuthenticationAgeSeconds) =>
            onChange({ ...draft, maxAuthenticationAgeSeconds })
          }
        />
      </div>
      <div className="platform-idp-readonly-policy">
        <LockKeyhole aria-hidden="true" />
        <span>
          <strong>Assertion encryption: disabled</strong>
          <small>
            Create cannot select optional or required until write-only SP-key
            management exists.
          </small>
        </span>
      </div>
    </fieldset>
  );
}

function AuditReasonField({
  disabled = false,
  id,
  onChange,
  value,
}: {
  disabled?: boolean;
  id: string;
  onChange: (value: string) => void;
  value: string;
}): React.JSX.Element {
  return (
    <TextareaField
      disabled={disabled}
      hint="Sent only in X-Audit-Reason. Do not include secrets, tokens, assertions, claims, subjects, metadata, or customer data."
      id={id}
      label="Audit reason"
      value={value}
      onChange={onChange}
    />
  );
}

function TextInputField({
  autoComplete,
  className,
  disabled = false,
  hint,
  id,
  label,
  onChange,
  optional = false,
  readOnly = false,
  type = "text",
  value,
}: {
  autoComplete?: string;
  className?: string;
  disabled?: boolean;
  hint?: string;
  id: string;
  label: string;
  onChange: (value: string) => void;
  optional?: boolean;
  readOnly?: boolean;
  type?: React.HTMLInputTypeAttribute;
  value: string;
}): React.JSX.Element {
  return (
    <div className={className}>
      <FormField
        htmlFor={id}
        label={label}
        {...(hint ? { hint } : {})}
        {...(optional ? { optional: true } : {})}
      >
        <Input
          {...(autoComplete ? { autoComplete } : {})}
          aria-describedby={hint ? `${id}-hint` : undefined}
          disabled={disabled}
          id={id}
          readOnly={readOnly}
          type={type}
          value={value}
          onChange={(event) => onChange(event.currentTarget.value)}
        />
      </FormField>
    </div>
  );
}

function TextareaField({
  className,
  disabled = false,
  hint,
  id,
  label,
  onChange,
  optional = false,
  value,
}: {
  className?: string;
  disabled?: boolean;
  hint?: string;
  id: string;
  label: string;
  onChange: (value: string) => void;
  optional?: boolean;
  value: string;
}): React.JSX.Element {
  return (
    <div className={className}>
      <FormField
        htmlFor={id}
        label={label}
        {...(hint ? { hint } : {})}
        {...(optional ? { optional: true } : {})}
      >
        <Textarea
          aria-describedby={hint ? `${id}-hint` : undefined}
          disabled={disabled}
          id={id}
          value={value}
          onChange={(event) => onChange(event.currentTarget.value)}
        />
      </FormField>
    </div>
  );
}

function SelectField<T extends string>({
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

function BooleanField({
  checked,
  hint,
  id,
  label,
  onChange,
}: {
  checked: boolean;
  hint: string;
  id: string;
  label: string;
  onChange: (value: boolean) => void;
}): React.JSX.Element {
  return (
    <div className="platform-idp-boolean-field">
      <Checkbox
        checked={checked}
        id={id}
        onCheckedChange={(value) => onChange(value === true)}
      />
      <div>
        <Label htmlFor={id}>{label}</Label>
        <p>{hint}</p>
      </div>
    </div>
  );
}

function Fact({
  code = false,
  label,
  value,
}: {
  code?: boolean;
  label: string;
  value: string;
}): React.JSX.Element {
  return (
    <div>
      <dt>{label}</dt>
      <dd>{code ? <code>{value}</code> : value}</dd>
    </div>
  );
}

function ValidationSummary({
  errors,
}: {
  errors: readonly string[];
}): React.JSX.Element {
  const titleId = useId();
  return (
    <Alert variant="destructive" aria-labelledby={titleId}>
      <ShieldAlert aria-hidden="true" />
      <AlertTitle id={titleId}>Review the provider definition</AlertTitle>
      <AlertDescription>
        <ul>
          {errors.map((error) => (
            <li key={error}>{error}</li>
          ))}
        </ul>
      </AlertDescription>
    </Alert>
  );
}

function ProviderStateBadge({
  provider,
}: {
  provider: PlatformAuthProviderSummaryView;
}): React.JSX.Element {
  if (provider.archivedAt !== null) {
    return (
      <Badge variant="outline">
        <Archive aria-hidden="true" /> Archived
      </Badge>
    );
  }
  if (provider.enabled) {
    if (provider.kind === "ldap") {
      return (
        <Badge>
          <ShieldCheck aria-hidden="true" /> LDAP platform login active
        </Badge>
      );
    }
    return (
      <Badge>
        <ShieldCheck aria-hidden="true" />
        {provider.platformLoginEnabled
          ? "Tenant + platform login active"
          : "Tenant execution active"}
      </Badge>
    );
  }
  return provider.activationAvailable ? (
    <Badge variant="secondary">
      <ShieldAlert aria-hidden="true" /> Ready to activate
    </Badge>
  ) : (
    <Badge variant="secondary">
      <CircleSlash2 aria-hidden="true" /> Staged · disabled
    </Badge>
  );
}

function ProviderListSkeleton(): React.JSX.Element {
  return (
    <Card aria-busy="true" aria-label="Loading platform identity providers">
      <CardHeader>
        <div className="skeleton-line skeleton-line--title" />
        <div className="skeleton-line" />
      </CardHeader>
      <CardContent className="platform-idp-skeleton-grid">
        <div className="skeleton-line" />
        <div className="skeleton-line" />
        <div className="skeleton-line" />
      </CardContent>
    </Card>
  );
}

function ProviderDetailSkeleton(): React.JSX.Element {
  return (
    <div
      className="platform-idp-skeleton-grid"
      aria-busy="true"
      aria-label="Loading provider detail"
    >
      <div className="skeleton-line skeleton-line--title" />
      <div className="skeleton-line" />
      <div className="skeleton-line" />
    </div>
  );
}

function kindLabel(kind: PlatformAuthProviderKind): string {
  if (kind === "oidc") return "OIDC";
  return kind === "ldap" ? "LDAP" : "SAML 2.0";
}

function humanizeToken(value: string): string {
  return value
    .split("_")
    .map((part) => `${part.slice(0, 1).toUpperCase()}${part.slice(1)}`)
    .join(" ");
}

function isAbortError(caught: unknown): boolean {
  return caught instanceof DOMException && caught.name === "AbortError";
}

function readBrowserPublicOrigin(): string | null {
  try {
    return typeof globalThis.location === "undefined"
      ? null
      : globalThis.location.origin;
  } catch {
    return null;
  }
}
