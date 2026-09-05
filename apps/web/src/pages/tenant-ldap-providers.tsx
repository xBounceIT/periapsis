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
  ArrowDown,
  Cable,
  CheckCircle2,
  KeyRound,
  LockKeyhole,
  Plus,
  RefreshCw,
  Save,
  ServerCog,
  ShieldAlert,
  Trash2,
  XCircle,
} from "lucide-react";
import { useCallback, useEffect, useId, useRef, useState } from "react";

import { useSession } from "../auth/session-context";
import { useTenantAuthority } from "../auth/tenant-authority-context";
import { FocusedError } from "../components/focused-error";
import { FormField } from "../components/form-field";
import { ServerDenied } from "../components/server-denied";
import { idempotencyKeyForPayload } from "../lib/payload-idempotency";
import {
  describePhaseTwoError,
  PhaseTwoApiError,
  tenantProjectionMismatchCode,
  type PhaseTwoApi,
  type TenantLdapAuthProviderConfigurationView,
  type TenantLdapAuthProviderDiagnosticView,
  type TenantLdapAuthProviderEndpointView,
  type TenantLdapAuthProviderSummaryView,
  type TenantLdapAuthProviderView,
  type VersionedView,
} from "../lib/phase-two-types";
import {
  createLdapProviderDraft,
  diagnosticCategoryLabel,
  draftFromLdapProvider,
  ldapTemplateOptions,
  providerIdFromLocation,
  toLdapProviderCreateInput,
  toLdapProviderUpdateInput,
  validateAdministrativeReason,
  validateBindSecret,
  validateLdapProviderDraft,
  type LdapProviderDraft,
  type LdapTemplateKind,
} from "./ldap-provider-model";
import { LdapAdministrationWorkspace } from "./ldap-administration-workspace";

type ProviderListState =
  | { kind: "error"; message: string }
  | { kind: "forbidden" }
  | { kind: "loading" }
  | {
      items: readonly TenantLdapAuthProviderSummaryView[];
      kind: "ready";
      nextCursor?: string;
    };

type ProviderDetailState =
  | {
      kind: "error";
      message: string;
      staleValue?: VersionedView<TenantLdapAuthProviderView>;
    }
  | { kind: "loading"; staleValue?: VersionedView<TenantLdapAuthProviderView> }
  | { kind: "ready"; value: VersionedView<TenantLdapAuthProviderView> };

interface MutationNotice {
  message: string;
  tone: "success" | "warning";
}

export function TenantLdapProvidersPage(): React.JSX.Element {
  const { api, clearSession, session } = useSession();
  const authority = useTenantAuthority();
  const tenantId = session.activeTenantId;
  const pairKey = authority.pairKey;
  const pairKeyRef = useRef(pairKey);
  pairKeyRef.current = pairKey;
  const canRead = authority.hasPermission("identity_provider.read", "tenant");
  const canManage = authority.hasPermission(
    "identity_provider.manage",
    "tenant",
  );
  const canTest = authority.hasPermission("identity_provider.test", "tenant");
  const canMappingRead = authority.hasPermission(
    "identity_mapping.read",
    "tenant",
  );
  const canMappingManage = authority.hasPermission(
    "identity_mapping.manage",
    "tenant",
  );
  const canSync = authority.hasPermission("identity_sync.run", "tenant");
  const [listState, setListState] = useState<ProviderListState>({
    kind: "loading",
  });
  const [revision, setRevision] = useState(0);
  const [selectedProviderId, setSelectedProviderId] = useState<string | null>(
    null,
  );
  const [createOpen, setCreateOpen] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const [paginationError, setPaginationError] = useState<string | null>(null);
  const [notice, setNotice] = useState<MutationNotice | null>(null);
  const cursorHistoryRef = useRef(new Set<string>());

  const handleRequestError = useCallback(
    (caught: unknown, expectedPair: string): "handled" | "unhandled" => {
      if (
        pairKeyRef.current !== expectedPair ||
        !(caught instanceof PhaseTwoApiError)
      ) {
        return "unhandled";
      }
      if (caught.status === 401) {
        clearSession(session.id);
        return "handled";
      }
      if (
        caught.status === 403 ||
        caught.code === tenantProjectionMismatchCode
      ) {
        authority.reload();
        return "handled";
      }
      return "unhandled";
    },
    [authority, clearSession, session.id],
  );

  useEffect(() => {
    setSelectedProviderId(null);
    setCreateOpen(false);
    setNotice(null);
    setPaginationError(null);
    setLoadingMore(false);
    cursorHistoryRef.current.clear();
  }, [pairKey]);

  useEffect(() => {
    if (!tenantId || authority.status !== "ready" || !canRead) {
      setListState(
        authority.status === "ready" && tenantId && !canRead
          ? { kind: "forbidden" }
          : { kind: "loading" },
      );
      return undefined;
    }
    const controller = new AbortController();
    const expectedPair = pairKey;
    cursorHistoryRef.current.clear();
    setListState((current) =>
      current.kind === "ready" ? current : { kind: "loading" },
    );
    setPaginationError(null);
    void api
      .listTenantLdapAuthProviders(tenantId, {
        includeArchived: true,
        signal: controller.signal,
      })
      .then((page) => {
        if (controller.signal.aborted || pairKeyRef.current !== expectedPair)
          return;
        if (page.nextCursor) cursorHistoryRef.current.add(page.nextCursor);
        setListState({
          items: mergeProviderSummaries([], page.items, tenantId),
          kind: "ready",
          ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
        });
      })
      .catch((caught: unknown) => {
        if (
          controller.signal.aborted ||
          pairKeyRef.current !== expectedPair ||
          isAbortError(caught)
        )
          return;
        if (handleRequestError(caught, expectedPair) === "handled") {
          if (caught instanceof PhaseTwoApiError && caught.status === 403) {
            setListState({ kind: "forbidden" });
          }
          return;
        }
        setListState({
          kind: "error",
          message: describePhaseTwoError(
            caught,
            "The LDAP provider inventory could not be loaded.",
          ),
        });
      });
    return () => controller.abort();
  }, [
    api,
    authority.status,
    canRead,
    handleRequestError,
    pairKey,
    revision,
    tenantId,
  ]);

  async function loadMore(): Promise<void> {
    if (
      !tenantId ||
      listState.kind !== "ready" ||
      !listState.nextCursor ||
      loadingMore
    ) {
      return;
    }
    const cursor = listState.nextCursor;
    const expectedPair = pairKey;
    setLoadingMore(true);
    setPaginationError(null);
    try {
      const page = await api.listTenantLdapAuthProviders(tenantId, {
        after: cursor,
        includeArchived: true,
      });
      if (pairKeyRef.current !== expectedPair) return;
      if (
        page.nextCursor === cursor ||
        (page.nextCursor && cursorHistoryRef.current.has(page.nextCursor))
      ) {
        throw new Error("The LDAP provider cursor did not advance.");
      }
      if (page.nextCursor) cursorHistoryRef.current.add(page.nextCursor);
      setListState((current) =>
        current.kind === "ready" && current.nextCursor === cursor
          ? {
              items: mergeProviderSummaries(
                current.items,
                page.items,
                tenantId,
              ),
              kind: "ready",
              ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
            }
          : current,
      );
    } catch (caught) {
      if (
        pairKeyRef.current !== expectedPair ||
        handleRequestError(caught, expectedPair) === "handled"
      )
        return;
      setPaginationError(
        describePhaseTwoError(
          caught,
          "More LDAP providers could not be loaded.",
        ),
      );
    } finally {
      if (pairKeyRef.current === expectedPair) setLoadingMore(false);
    }
  }

  if (!tenantId) {
    return (
      <div className="content content--narrow">
        <section className="page-heading">
          <div>
            <p className="section-label">Tenant administration</p>
            <h1>Select a tenant to manage identity providers.</h1>
            <p>
              The tenant switcher establishes the explicit authorization and RLS
              context.
            </p>
          </div>
        </section>
      </div>
    );
  }
  if (authority.status === "forbidden" || listState.kind === "forbidden") {
    return <ServerDenied resource="tenant LDAP providers" />;
  }
  if (authority.status === "error") {
    return (
      <div className="content content--narrow">
        <FocusedError
          message={authority.message ?? "Tenant authority could not be loaded."}
        />
        <Button type="button" variant="outline" onClick={authority.reload}>
          <RefreshCw aria-hidden="true" /> Reload tenant authority
        </Button>
      </div>
    );
  }
  if (authority.status !== "ready" || listState.kind === "loading") {
    return <LdapProviderSkeleton />;
  }
  if (!canRead) return <ServerDenied resource="tenant LDAP providers" />;

  return (
    <div className="content ldap-provider-page">
      <section className="page-heading ldap-provider-page__heading">
        <div>
          <p className="section-label">Tenant administration</p>
          <h1>LDAP identity providers</h1>
          <p>
            Configure TLS-protected directory endpoints, redacted bind-secret
            state, and bounded connection diagnostics. Visibility here is an
            affordance; the API rechecks every permission.
          </p>
        </div>
        {canManage ? (
          <Button type="button" onClick={() => setCreateOpen(true)}>
            <Plus aria-hidden="true" /> Create provider
          </Button>
        ) : null}
      </section>

      {notice ? (
        <Alert className="ldap-provider-notice">
          {notice.tone === "success" ? (
            <CheckCircle2 aria-hidden="true" />
          ) : (
            <ShieldAlert aria-hidden="true" />
          )}
          <AlertTitle>
            {notice.tone === "success" ? "Action completed" : "Review needed"}
          </AlertTitle>
          <AlertDescription>{notice.message}</AlertDescription>
        </Alert>
      ) : null}

      {listState.kind === "error" ? (
        <div className="ldap-provider-list-error">
          <FocusedError message={listState.message} />
          <Button
            type="button"
            variant="outline"
            onClick={() => setRevision((value) => value + 1)}
          >
            <RefreshCw aria-hidden="true" /> Retry inventory
          </Button>
        </div>
      ) : (
        <Card className="ldap-provider-table-card">
          <CardHeader>
            <CardTitle>Provider inventory</CardTitle>
            <CardDescription>
              Bind secrets are represented only by configured/rotated metadata.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Table className="ldap-provider-table">
              <TableCaption>
                {listState.items.length === 0
                  ? "No LDAP providers are configured for this tenant."
                  : `${listState.items.length} LDAP provider${listState.items.length === 1 ? "" : "s"} loaded.`}
              </TableCaption>
              <TableHeader>
                <TableRow>
                  <TableHead>Provider</TableHead>
                  <TableHead>Template</TableHead>
                  <TableHead>Endpoints</TableHead>
                  <TableHead>Bind secret</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {listState.items.map((provider) => (
                  <TableRow key={provider.id}>
                    <TableCell>
                      <div className="ldap-provider-name-cell">
                        <strong>{provider.displayName}</strong>
                        <small>{provider.key}</small>
                      </div>
                    </TableCell>
                    <TableCell>{templateLabel(provider.template)}</TableCell>
                    <TableCell>
                      {provider.enabledEndpointCount} enabled
                    </TableCell>
                    <TableCell>
                      {provider.bindSecretConfigured ? "Configured" : "Not set"}
                    </TableCell>
                    <TableCell>
                      <ProviderStateBadge provider={provider} />
                    </TableCell>
                    <TableCell className="text-right">
                      <Button
                        type="button"
                        size="sm"
                        variant="outline"
                        onClick={() => setSelectedProviderId(provider.id)}
                      >
                        Inspect
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            {listState.nextCursor ? (
              <div className="ldap-provider-pagination">
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => void loadMore()}
                  disabled={loadingMore}
                >
                  <ArrowDown aria-hidden="true" />
                  {loadingMore ? "Loading…" : "Load more providers"}
                </Button>
                {paginationError ? (
                  <FocusedError message={paginationError} />
                ) : null}
              </div>
            ) : null}
          </CardContent>
        </Card>
      )}

      <CreateLdapProviderDialog
        api={api}
        canManage={canManage}
        csrfToken={session.csrfToken}
        onCreated={(location) => {
          setCreateOpen(false);
          setNotice({
            message:
              "The provider was created disabled. Add a bind secret and review readiness before enabling it.",
            tone: "success",
          });
          setRevision((value) => value + 1);
          const providerId = providerIdFromLocation(location);
          if (providerId) setSelectedProviderId(providerId);
        }}
        onOpenChange={setCreateOpen}
        onPermissionError={authority.reload}
        onUnauthenticated={() => clearSession(session.id)}
        open={createOpen}
        pairKey={pairKey}
        tenantId={tenantId}
      />

      <LdapProviderDetailDialog
        api={api}
        canManage={canManage}
        canMappingManage={canMappingManage}
        canMappingRead={canMappingRead}
        canRead={canRead}
        canSync={canSync}
        canTest={canTest}
        csrfToken={session.csrfToken}
        onArchived={() => {
          setSelectedProviderId(null);
          setNotice({
            message: "The LDAP provider was archived and disabled.",
            tone: "success",
          });
          setRevision((value) => value + 1);
        }}
        onListRefresh={() => setRevision((value) => value + 1)}
        onNotice={setNotice}
        onOpenChange={(open) => {
          if (!open) setSelectedProviderId(null);
        }}
        onPermissionError={authority.reload}
        onUnauthenticated={() => clearSession(session.id)}
        open={selectedProviderId !== null}
        pairKey={pairKey}
        providerId={selectedProviderId}
        tenantId={tenantId}
      />
    </div>
  );
}

interface CreateDialogProps {
  api: PhaseTwoApi;
  canManage: boolean;
  csrfToken: string;
  onCreated: (location: string) => void;
  onOpenChange: (open: boolean) => void;
  onPermissionError: () => void;
  onUnauthenticated: () => void;
  open: boolean;
  pairKey: string;
  tenantId: string;
}

function CreateLdapProviderDialog({
  api,
  canManage,
  csrfToken,
  onCreated,
  onOpenChange,
  onPermissionError,
  onUnauthenticated,
  open,
  pairKey,
  tenantId,
}: CreateDialogProps): React.JSX.Element {
  const [template, setTemplate] =
    useState<LdapTemplateKind>("active_directory");
  const [draft, setDraft] = useState(() => createLdapProviderDraft(template));
  const [errors, setErrors] = useState<readonly string[]>([]);
  const [requestError, setRequestError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const idempotencyBindingRef = useRef<{
    fingerprint: string;
    key: string;
  } | null>(null);
  const requestPairRef = useRef(pairKey);
  requestPairRef.current = pairKey;

  useEffect(() => {
    setTemplate("active_directory");
    setDraft(createLdapProviderDraft("active_directory"));
    setErrors([]);
    setRequestError(null);
    setSubmitting(false);
    idempotencyBindingRef.current = null;
  }, [pairKey]);

  useEffect(() => {
    if (!canManage && open) onOpenChange(false);
  }, [canManage, onOpenChange, open]);

  function changeTemplate(next: LdapTemplateKind): void {
    setTemplate(next);
    setDraft(createLdapProviderDraft(next));
    setErrors([]);
    setRequestError(null);
    idempotencyBindingRef.current = null;
  }

  async function submit(
    event: React.FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault();
    if (!canManage || submitting) return;
    const validationErrors = validateLdapProviderDraft(draft);
    setErrors(validationErrors);
    setRequestError(null);
    if (validationErrors.length > 0) return;
    const input = toLdapProviderCreateInput(draft);
    const idempotencyKey = idempotencyKeyForPayload(idempotencyBindingRef, {
      input,
      tenantId,
    });
    const expectedPair = pairKey;
    setSubmitting(true);
    try {
      const created = await api.createTenantLdapAuthProvider(
        csrfToken,
        tenantId,
        idempotencyKey,
        input,
      );
      if (requestPairRef.current !== expectedPair) return;
      idempotencyBindingRef.current = null;
      onCreated(created.location);
    } catch (caught) {
      if (requestPairRef.current !== expectedPair) return;
      if (caught instanceof PhaseTwoApiError && caught.status === 401) {
        onUnauthenticated();
        return;
      }
      if (caught instanceof PhaseTwoApiError && caught.status === 403) {
        onPermissionError();
      }
      setRequestError(
        describePhaseTwoError(
          caught,
          "The provider was not created. The same unchanged request can be retried safely.",
        ),
      );
    } finally {
      if (requestPairRef.current === expectedPair) setSubmitting(false);
    }
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (!submitting) onOpenChange(next);
      }}
    >
      <DialogContent className="ldap-provider-editor-dialog">
        <DialogHeader>
          <DialogTitle>Create LDAP provider</DialogTitle>
          <DialogDescription>
            Start from a safe editable directory template. New providers are
            always created disabled and never accept a bind secret here.
          </DialogDescription>
        </DialogHeader>
        <div
          className="ldap-template-picker"
          role="group"
          aria-label="Starting template"
        >
          {ldapTemplateOptions.map((option) => (
            <button
              className={
                template === option.value
                  ? "ldap-template-card ldap-template-card--active"
                  : "ldap-template-card"
              }
              key={option.value}
              onClick={() => changeTemplate(option.value)}
              type="button"
            >
              <strong>{option.label}</strong>
              <span>{option.description}</span>
            </button>
          ))}
        </div>
        <form
          className="ldap-provider-form"
          onSubmit={(event) => void submit(event)}
        >
          <LdapProviderEditor draft={draft} mode="create" onChange={setDraft} />
          {errors.length > 0 ? <ValidationSummary errors={errors} /> : null}
          {requestError ? <FocusedError message={requestError} /> : null}
          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => onOpenChange(false)}
              disabled={submitting}
            >
              Cancel
            </Button>
            <Button type="submit" disabled={submitting || !canManage}>
              <Plus aria-hidden="true" />{" "}
              {submitting ? "Creating…" : "Create disabled provider"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

interface DetailDialogProps {
  api: PhaseTwoApi;
  canManage: boolean;
  canMappingManage: boolean;
  canMappingRead: boolean;
  canRead: boolean;
  canSync: boolean;
  canTest: boolean;
  csrfToken: string;
  onArchived: () => void;
  onListRefresh: () => void;
  onNotice: (notice: MutationNotice) => void;
  onOpenChange: (open: boolean) => void;
  onPermissionError: () => void;
  onUnauthenticated: () => void;
  open: boolean;
  pairKey: string;
  providerId: string | null;
  tenantId: string;
}

function LdapProviderDetailDialog(props: DetailDialogProps): React.JSX.Element {
  const {
    api,
    canManage,
    canMappingManage,
    canMappingRead,
    canRead,
    canSync,
    canTest,
    csrfToken,
    onArchived,
    onListRefresh,
    onNotice,
    onOpenChange,
    onPermissionError,
    onUnauthenticated,
    open,
    pairKey,
    providerId,
    tenantId,
  } = props;
  const [state, setState] = useState<ProviderDetailState>({ kind: "loading" });
  const [refreshRevision, setRefreshRevision] = useState(0);
  const [editOpen, setEditOpen] = useState(false);
  const [secretOpen, setSecretOpen] = useState(false);
  const [clearOpen, setClearOpen] = useState(false);
  const [archiveOpen, setArchiveOpen] = useState(false);
  const [diagnostic, setDiagnostic] =
    useState<TenantLdapAuthProviderDiagnosticView | null>(null);
  const [diagnosticError, setDiagnosticError] = useState<string | null>(null);
  const [testing, setTesting] = useState<"bind" | "connection" | null>(null);
  const pairRef = useRef(pairKey);
  pairRef.current = pairKey;
  const testControllerRef = useRef<AbortController | null>(null);

  useEffect(() => {
    setState({ kind: "loading" });
    setEditOpen(false);
    setSecretOpen(false);
    setClearOpen(false);
    setArchiveOpen(false);
    setDiagnostic(null);
    setDiagnosticError(null);
    setTesting(null);
    testControllerRef.current?.abort();
    testControllerRef.current = null;
  }, [pairKey, providerId]);

  useEffect(() => {
    if (!open || !providerId || !canRead) return undefined;
    const controller = new AbortController();
    const expectedPair = pairKey;
    setState((current) => {
      const staleValue =
        current.kind === "ready"
          ? current.value
          : "staleValue" in current
            ? current.staleValue
            : undefined;
      return {
        kind: "loading",
        ...(staleValue ? { staleValue } : {}),
      };
    });
    void api
      .getTenantLdapAuthProvider(tenantId, providerId, controller.signal)
      .then((provider) => {
        if (controller.signal.aborted || pairRef.current !== expectedPair)
          return;
        setState({ kind: "ready", value: provider });
      })
      .catch((caught: unknown) => {
        if (
          controller.signal.aborted ||
          pairRef.current !== expectedPair ||
          isAbortError(caught)
        )
          return;
        if (caught instanceof PhaseTwoApiError && caught.status === 401) {
          onUnauthenticated();
          return;
        }
        if (caught instanceof PhaseTwoApiError && caught.status === 403)
          onPermissionError();
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
              "The LDAP provider detail could not be loaded.",
            ),
            ...(staleValue ? { staleValue } : {}),
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
    pairKey,
    providerId,
    refreshRevision,
    tenantId,
  ]);

  useEffect(() => () => testControllerRef.current?.abort(), []);

  const coherentVersioned = state.kind === "ready" ? state.value : undefined;
  const staleVersioned =
    state.kind !== "ready" && "staleValue" in state
      ? state.staleValue
      : undefined;
  const displayVersioned = coherentVersioned ?? staleVersioned;
  const provider = displayVersioned?.value;

  function mutationSucceeded(message: string): void {
    if (coherentVersioned) {
      setState({
        kind: "loading",
        staleValue: coherentVersioned,
      });
    }
    onNotice({ message, tone: "success" });
    onListRefresh();
    if (canRead) setRefreshRevision((value) => value + 1);
  }

  async function runDiagnostic(kind: "bind" | "connection"): Promise<void> {
    if (!providerId || !canTest || testing || state.kind !== "ready") return;
    testControllerRef.current?.abort();
    const controller = new AbortController();
    testControllerRef.current = controller;
    const expectedPair = pairKey;
    setTesting(kind);
    setDiagnostic(null);
    setDiagnosticError(null);
    try {
      const result =
        kind === "connection"
          ? await api.testTenantLdapAuthProviderConnection(
              csrfToken,
              tenantId,
              providerId,
              controller.signal,
            )
          : await api.testTenantLdapAuthProviderBind(
              csrfToken,
              tenantId,
              providerId,
              controller.signal,
            );
      if (controller.signal.aborted || pairRef.current !== expectedPair) return;
      setDiagnostic(result);
    } catch (caught) {
      if (
        controller.signal.aborted ||
        pairRef.current !== expectedPair ||
        isAbortError(caught)
      )
        return;
      if (caught instanceof PhaseTwoApiError && caught.status === 401) {
        onUnauthenticated();
        return;
      }
      if (caught instanceof PhaseTwoApiError && caught.status === 403)
        onPermissionError();
      setDiagnosticError(
        describePhaseTwoError(
          caught,
          "The bounded LDAP diagnostic could not be completed.",
        ),
      );
    } finally {
      if (testControllerRef.current === controller)
        testControllerRef.current = null;
      if (pairRef.current === expectedPair) setTesting(null);
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="ldap-provider-detail-dialog">
        <DialogHeader>
          <DialogTitle>{provider?.displayName ?? "LDAP provider"}</DialogTitle>
          <DialogDescription>
            Current redacted configuration and dedicated operational actions.
          </DialogDescription>
        </DialogHeader>
        {state.kind === "loading" && !provider ? <LdapDetailSkeleton /> : null}
        {state.kind === "error" ? (
          <div className="ldap-provider-detail-error">
            <FocusedError message={state.message} />
            <Button
              type="button"
              variant="outline"
              onClick={() => setRefreshRevision((value) => value + 1)}
            >
              <RefreshCw aria-hidden="true" /> Reload detail
            </Button>
          </div>
        ) : null}
        {provider && displayVersioned ? (
          <div className="ldap-provider-detail-ready">
            {state.kind !== "ready" ? (
              <Alert>
                <ShieldAlert aria-hidden="true" />
                <AlertTitle>Showing the last confirmed projection</AlertTitle>
                <AlertDescription>
                  The preceding mutation succeeded, but the read refresh has not
                  completed. The last confirmed body remains display-only with
                  its original ETag; actions stay locked until a successful GET
                  returns a new coherent body and ETag.
                </AlertDescription>
              </Alert>
            ) : null}
            <ProviderFacts provider={provider} />
            <EndpointRail endpoints={provider.endpoints} />
            {coherentVersioned ? (
              <section
                className="ldap-provider-actions"
                aria-labelledby="ldap-actions-title"
              >
                <div className="ldap-provider-section-heading">
                  <div>
                    <h3 id="ldap-actions-title">Provider actions</h3>
                    <p>Each action is re-authorized by the server.</p>
                  </div>
                </div>
                <div className="ldap-provider-action-grid">
                  {canManage && provider.archivedAt === null ? (
                    <>
                      <Button
                        type="button"
                        variant="outline"
                        onClick={() => setEditOpen(true)}
                      >
                        <ServerCog aria-hidden="true" /> Edit configuration
                      </Button>
                      <Button
                        type="button"
                        variant="outline"
                        onClick={() => setSecretOpen(true)}
                      >
                        <KeyRound aria-hidden="true" />{" "}
                        {provider.bindSecretConfigured
                          ? "Replace bind secret"
                          : "Set bind secret"}
                      </Button>
                      <Button
                        type="button"
                        variant="outline"
                        disabled={
                          provider.enabled || !provider.bindSecretConfigured
                        }
                        onClick={() => setClearOpen(true)}
                      >
                        <Trash2 aria-hidden="true" /> Clear bind secret
                      </Button>
                      <Button
                        type="button"
                        variant="destructive"
                        onClick={() => setArchiveOpen(true)}
                      >
                        <Archive aria-hidden="true" /> Archive provider
                      </Button>
                    </>
                  ) : null}
                  {canTest && provider.archivedAt === null ? (
                    <>
                      <Button
                        type="button"
                        variant="outline"
                        disabled={testing !== null}
                        onClick={() => void runDiagnostic("connection")}
                      >
                        <Cable aria-hidden="true" />{" "}
                        {testing === "connection"
                          ? "Testing connection…"
                          : "Test connection"}
                      </Button>
                      <Button
                        type="button"
                        variant="outline"
                        disabled={
                          testing !== null || !provider.bindSecretConfigured
                        }
                        onClick={() => void runDiagnostic("bind")}
                      >
                        <LockKeyhole aria-hidden="true" />{" "}
                        {testing === "bind" ? "Testing bind…" : "Test bind"}
                      </Button>
                    </>
                  ) : null}
                </div>
              </section>
            ) : null}
            {diagnostic ? <DiagnosticPanel diagnostic={diagnostic} /> : null}
            {diagnosticError ? (
              <FocusedError
                message={diagnosticError}
                title="Diagnostic request failed"
              />
            ) : null}
            {coherentVersioned && provider.archivedAt === null ? (
              <LdapAdministrationWorkspace
                api={api}
                canMappingManage={canMappingManage}
                canMappingRead={canMappingRead}
                canProviderManage={canManage}
                canProviderTest={canTest}
                canSync={canSync}
                csrfToken={csrfToken}
                onPermissionError={onPermissionError}
                onUnauthenticated={onUnauthenticated}
                pairKey={pairKey}
                providerId={provider.id}
                tenantId={tenantId}
              />
            ) : null}
          </div>
        ) : null}

        {provider && coherentVersioned ? (
          <>
            <EditProviderDialog
              api={api}
              csrfToken={csrfToken}
              onMutation={mutationSucceeded}
              onOpenChange={setEditOpen}
              onPermissionError={onPermissionError}
              onUnauthenticated={onUnauthenticated}
              open={editOpen}
              pairKey={pairKey}
              tenantId={tenantId}
              versioned={coherentVersioned}
            />
            <BindSecretDialog
              api={api}
              csrfToken={csrfToken}
              onMutation={mutationSucceeded}
              onOpenChange={setSecretOpen}
              onPermissionError={onPermissionError}
              onUnauthenticated={onUnauthenticated}
              open={secretOpen}
              pairKey={pairKey}
              tenantId={tenantId}
              versioned={coherentVersioned}
            />
            <ReasonMutationDialog
              action="clear"
              api={api}
              csrfToken={csrfToken}
              onMutation={mutationSucceeded}
              onOpenChange={setClearOpen}
              onPermissionError={onPermissionError}
              onUnauthenticated={onUnauthenticated}
              open={clearOpen}
              pairKey={pairKey}
              tenantId={tenantId}
              versioned={coherentVersioned}
            />
            <ReasonMutationDialog
              action="archive"
              api={api}
              csrfToken={csrfToken}
              onArchived={onArchived}
              onMutation={mutationSucceeded}
              onOpenChange={setArchiveOpen}
              onPermissionError={onPermissionError}
              onUnauthenticated={onUnauthenticated}
              open={archiveOpen}
              pairKey={pairKey}
              tenantId={tenantId}
              versioned={coherentVersioned}
            />
          </>
        ) : null}
      </DialogContent>
    </Dialog>
  );
}

interface MutationDialogBaseProps {
  api: PhaseTwoApi;
  csrfToken: string;
  onMutation: (message: string) => void;
  onOpenChange: (open: boolean) => void;
  onPermissionError: () => void;
  onUnauthenticated: () => void;
  open: boolean;
  pairKey: string;
  tenantId: string;
  versioned: VersionedView<TenantLdapAuthProviderView>;
}

function EditProviderDialog(props: MutationDialogBaseProps): React.JSX.Element {
  const {
    api,
    csrfToken,
    onMutation,
    onOpenChange,
    onPermissionError,
    onUnauthenticated,
    open,
    pairKey,
    tenantId,
    versioned,
  } = props;
  const [draft, setDraft] = useState(() =>
    draftFromLdapProvider(versioned.value),
  );
  const [errors, setErrors] = useState<readonly string[]>([]);
  const [requestError, setRequestError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [stale, setStale] = useState(false);
  const pairRef = useRef(pairKey);
  pairRef.current = pairKey;

  useEffect(() => {
    if (!open) return;
    setDraft(draftFromLdapProvider(versioned.value));
    setErrors([]);
    setRequestError(null);
    setStale(false);
  }, [open, versioned]);

  async function submit(
    event: React.FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault();
    const validationErrors = validateLdapProviderDraft(draft);
    setErrors(validationErrors);
    setRequestError(null);
    if (validationErrors.length > 0 || submitting) return;
    const expectedPair = pairKey;
    setSubmitting(true);
    try {
      await api.updateTenantLdapAuthProvider(
        csrfToken,
        tenantId,
        versioned.value.id,
        versioned.etag,
        toLdapProviderUpdateInput(draft),
      );
      if (pairRef.current !== expectedPair) return;
      onOpenChange(false);
      onMutation("The full LDAP provider document was replaced successfully.");
    } catch (caught) {
      if (pairRef.current !== expectedPair) return;
      if (caught instanceof PhaseTwoApiError && caught.status === 401) {
        onUnauthenticated();
        return;
      }
      if (caught instanceof PhaseTwoApiError && caught.status === 403)
        onPermissionError();
      setStale(caught instanceof PhaseTwoApiError && caught.status === 412);
      setRequestError(
        describePhaseTwoError(
          caught,
          "The provider configuration was not replaced.",
        ),
      );
    } finally {
      if (pairRef.current === expectedPair) setSubmitting(false);
    }
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => !submitting && onOpenChange(next)}
    >
      <DialogContent className="ldap-provider-editor-dialog">
        <DialogHeader>
          <DialogTitle>Edit LDAP provider</DialogTitle>
          <DialogDescription>
            This is an atomic full replacement. The current ETag protects
            against overwriting another administrator.
          </DialogDescription>
        </DialogHeader>
        <form
          className="ldap-provider-form"
          onSubmit={(event) => void submit(event)}
        >
          <LdapProviderEditor draft={draft} mode="update" onChange={setDraft} />
          {errors.length > 0 ? <ValidationSummary errors={errors} /> : null}
          {stale ? (
            <Alert>
              <ShieldAlert aria-hidden="true" />
              <AlertTitle>Provider changed on the server</AlertTitle>
              <AlertDescription>
                Your draft is preserved. Close this editor, reload the detail,
                compare changes, and submit explicitly again.
              </AlertDescription>
            </Alert>
          ) : null}
          {requestError ? <FocusedError message={requestError} /> : null}
          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => onOpenChange(false)}
              disabled={submitting}
            >
              Cancel
            </Button>
            <Button type="submit" disabled={submitting || stale}>
              <Save aria-hidden="true" />{" "}
              {submitting ? "Saving…" : "Replace provider"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function BindSecretDialog(props: MutationDialogBaseProps): React.JSX.Element {
  const {
    api,
    csrfToken,
    onMutation,
    onOpenChange,
    onPermissionError,
    onUnauthenticated,
    open,
    pairKey,
    tenantId,
    versioned,
  } = props;
  const [secret, setSecret] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const pairRef = useRef(pairKey);
  pairRef.current = pairKey;

  useEffect(() => {
    setSecret("");
    setError(null);
    setSubmitting(false);
  }, [open, pairKey]);

  async function submit(
    event: React.FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault();
    const validationError = validateBindSecret(secret);
    setError(validationError);
    if (validationError || submitting) return;
    const expectedPair = pairKey;
    setSubmitting(true);
    try {
      await api.setTenantLdapAuthProviderBindSecret(
        csrfToken,
        tenantId,
        versioned.value.id,
        versioned.etag,
        { secret },
      );
      if (pairRef.current !== expectedPair) return;
      setSecret("");
      onOpenChange(false);
      onMutation(
        "The bind secret was encrypted and replaced. Its value is no longer available to the browser.",
      );
    } catch (caught) {
      if (pairRef.current !== expectedPair) return;
      if (caught instanceof PhaseTwoApiError && caught.status === 401) {
        setSecret("");
        onUnauthenticated();
        return;
      }
      if (caught instanceof PhaseTwoApiError && caught.status === 403)
        onPermissionError();
      setError(
        describePhaseTwoError(caught, "The bind secret was not replaced."),
      );
    } finally {
      if (pairRef.current === expectedPair) setSubmitting(false);
    }
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (!next) setSecret("");
        if (!submitting) onOpenChange(next);
      }}
    >
      <DialogContent className="ldap-provider-secret-dialog">
        <DialogHeader>
          <DialogTitle>
            {versioned.value.bindSecretConfigured ? "Replace" : "Set"} bind
            secret
          </DialogTitle>
          <DialogDescription>
            The value is write-only. It is cleared from this form immediately
            after storage and never shown again.
          </DialogDescription>
        </DialogHeader>
        <form
          className="ldap-provider-form"
          onSubmit={(event) => void submit(event)}
        >
          <FormField
            htmlFor="ldap-bind-secret"
            label="Bind secret"
            {...(error ? { error } : {})}
            hint="Maximum 8176 UTF-8 bytes."
          >
            <Input
              autoComplete="new-password"
              id="ldap-bind-secret"
              name="secret"
              onChange={(event) => setSecret(event.currentTarget.value)}
              type="password"
              value={secret}
            />
          </FormField>
          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => onOpenChange(false)}
              disabled={submitting}
            >
              Cancel
            </Button>
            <Button type="submit" disabled={submitting}>
              <KeyRound aria-hidden="true" />{" "}
              {submitting ? "Encrypting…" : "Store write-only secret"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

interface ReasonMutationDialogProps extends MutationDialogBaseProps {
  action: "archive" | "clear";
  onArchived?: () => void;
}

function ReasonMutationDialog({
  action,
  api,
  csrfToken,
  onArchived,
  onMutation,
  onOpenChange,
  onPermissionError,
  onUnauthenticated,
  open,
  pairKey,
  tenantId,
  versioned,
}: ReasonMutationDialogProps): React.JSX.Element {
  const [reason, setReason] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const pairRef = useRef(pairKey);
  pairRef.current = pairKey;

  useEffect(() => {
    setReason("");
    setError(null);
    setSubmitting(false);
  }, [open, pairKey]);

  async function submit(
    event: React.FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault();
    const normalized = reason.trim();
    const validationError = validateAdministrativeReason(normalized);
    setError(validationError);
    if (validationError || submitting) return;
    const expectedPair = pairKey;
    setSubmitting(true);
    try {
      if (action === "archive") {
        await api.archiveTenantLdapAuthProvider(
          csrfToken,
          tenantId,
          versioned.value.id,
          versioned.etag,
          { reason: normalized },
        );
      } else {
        await api.clearTenantLdapAuthProviderBindSecret(
          csrfToken,
          tenantId,
          versioned.value.id,
          versioned.etag,
          { reason: normalized },
        );
      }
      if (pairRef.current !== expectedPair) return;
      setReason("");
      onOpenChange(false);
      if (action === "archive") onArchived?.();
      else onMutation("The disabled provider bind secret was cleared.");
    } catch (caught) {
      if (pairRef.current !== expectedPair) return;
      if (caught instanceof PhaseTwoApiError && caught.status === 401) {
        onUnauthenticated();
        return;
      }
      if (caught instanceof PhaseTwoApiError && caught.status === 403)
        onPermissionError();
      setError(
        describePhaseTwoError(
          caught,
          action === "archive"
            ? "The provider was not archived."
            : "The bind secret was not cleared.",
        ),
      );
    } finally {
      if (pairRef.current === expectedPair) setSubmitting(false);
    }
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => !submitting && onOpenChange(next)}
    >
      <DialogContent className="ldap-provider-secret-dialog">
        <DialogHeader>
          <DialogTitle>
            {action === "archive"
              ? "Archive LDAP provider"
              : "Clear bind secret"}
          </DialogTitle>
          <DialogDescription>
            {action === "archive"
              ? "Archiving is permanent and disables the provider. It cannot be unarchived through this API."
              : "Clearing is available only while the provider is disabled and is recorded in the audit trail."}
          </DialogDescription>
        </DialogHeader>
        <form
          className="ldap-provider-form"
          onSubmit={(event) => void submit(event)}
        >
          <FormField
            htmlFor={`ldap-${action}-reason`}
            label="Audit reason"
            {...(error ? { error } : {})}
          >
            <Textarea
              id={`ldap-${action}-reason`}
              maxLength={500}
              onChange={(event) => setReason(event.currentTarget.value)}
              value={reason}
            />
          </FormField>
          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => onOpenChange(false)}
              disabled={submitting}
            >
              Cancel
            </Button>
            <Button
              type="submit"
              variant={action === "archive" ? "destructive" : "default"}
              disabled={submitting}
            >
              {action === "archive" ? (
                <Archive aria-hidden="true" />
              ) : (
                <Trash2 aria-hidden="true" />
              )}
              {submitting
                ? "Submitting…"
                : action === "archive"
                  ? "Archive permanently"
                  : "Clear secret"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

export interface LdapProviderEditorProps {
  draft: LdapProviderDraft;
  manageEnabled?: boolean;
  mode: "create" | "update";
  onChange: (draft: LdapProviderDraft) => void;
  policy?: "platform_global" | "tenant";
}

export function LdapProviderEditor({
  draft,
  manageEnabled = true,
  mode,
  onChange,
  policy = "tenant",
}: LdapProviderEditorProps): React.JSX.Element {
  const id = useId();
  const configuration = draft.configuration;

  function updateDraft(patch: Partial<LdapProviderDraft>): void {
    onChange({ ...draft, ...patch });
  }

  function updateConfiguration<
    K extends keyof TenantLdapAuthProviderConfigurationView,
  >(key: K, value: TenantLdapAuthProviderConfigurationView[K]): void {
    updateDraft({ configuration: { ...configuration, [key]: value } });
  }

  function updateEndpoint(
    index: number,
    patch: Partial<TenantLdapAuthProviderEndpointView>,
  ): void {
    updateDraft({
      endpoints: draft.endpoints.map((endpoint, endpointIndex) =>
        endpointIndex === index ? { ...endpoint, ...patch } : endpoint,
      ),
    });
  }

  function addEndpoint(): void {
    if (draft.endpoints.length >= 8) return;
    const nextPriority =
      Math.max(0, ...draft.endpoints.map((endpoint) => endpoint.priority)) + 1;
    updateDraft({
      endpoints: [
        ...draft.endpoints,
        {
          enabled: true,
          host: "ldap.example.org",
          port: 636,
          priority: Math.min(nextPriority, 8),
          referralAllowed: false,
          tlsServerName: "ldap.example.org",
          transport: "ldaps",
        },
      ],
    });
  }

  return (
    <div className="ldap-provider-editor">
      <fieldset className="ldap-provider-fieldset">
        <legend>Provider identity</legend>
        <div className="ldap-provider-form-grid">
          <FormField
            htmlFor={`${id}-key`}
            label="Key"
            hint="Lowercase stable identifier, 3–64 characters."
          >
            <Input
              id={`${id}-key`}
              maxLength={64}
              value={draft.key}
              onChange={(event) =>
                updateDraft({ key: event.currentTarget.value })
              }
            />
          </FormField>
          <FormField htmlFor={`${id}-display-name`} label="Display name">
            <Input
              id={`${id}-display-name`}
              maxLength={120}
              value={draft.displayName}
              onChange={(event) =>
                updateDraft({ displayName: event.currentTarget.value })
              }
            />
          </FormField>
        </div>
        <FormField htmlFor={`${id}-description`} label="Description" optional>
          <Textarea
            id={`${id}-description`}
            maxLength={1000}
            value={draft.description}
            onChange={(event) =>
              updateDraft({ description: event.currentTarget.value })
            }
          />
        </FormField>
        {mode === "update" && manageEnabled ? (
          <BooleanField
            checked={draft.enabled}
            id={`${id}-provider-enabled`}
            label="Provider enabled"
            onChange={(enabled) => updateDraft({ enabled })}
            hint="Enabling remains subject to server-side readiness checks."
          />
        ) : mode === "create" ? (
          <p className="ldap-provider-inline-note">
            Creation is always disabled.
          </p>
        ) : null}
      </fieldset>

      <fieldset className="ldap-provider-fieldset">
        <legend>Directory and TLS</legend>
        <div className="ldap-provider-form-grid">
          <NativeSelectField
            id={`${id}-configuration-template`}
            label="Configuration template"
            value={configuration.template}
            options={[
              ["active_directory", "Active Directory"],
              ["openldap", "OpenLDAP"],
              ["posix", "POSIX LDAP"],
              ["custom", "Custom"],
            ]}
            onChange={(value) => updateConfiguration("template", value)}
          />
          <ReadOnlyPolicy label="Certificate verification" value="Required" />
          <NumberField
            id={`${id}-connect-timeout`}
            label="Connect timeout (ms)"
            min={100}
            max={30000}
            value={configuration.connectTimeoutMs}
            onChange={(value) => updateConfiguration("connectTimeoutMs", value)}
          />
          <NumberField
            id={`${id}-operation-timeout`}
            label="Operation timeout (ms)"
            min={100}
            max={60000}
            value={configuration.operationTimeoutMs}
            onChange={(value) =>
              updateConfiguration("operationTimeoutMs", value)
            }
          />
        </div>
        <FormField
          htmlFor={`${id}-custom-ca`}
          label="Custom CA PEM"
          optional
          hint="Appended to an isolated copy of system roots; CA certificates only."
        >
          <Textarea
            id={`${id}-custom-ca`}
            className="ldap-provider-code-input"
            value={configuration.customCaPem ?? ""}
            onChange={(event) =>
              updateConfiguration(
                "customCaPem",
                nullable(event.currentTarget.value),
              )
            }
          />
        </FormField>
        <div className="ldap-provider-form-grid">
          <TextField
            id={`${id}-bind-dn`}
            label="Bind DN"
            value={configuration.bindDn}
            onChange={(value) => updateConfiguration("bindDn", value)}
          />
          <TextField
            id={`${id}-user-base-dn`}
            label="User base DN"
            value={configuration.userBaseDn}
            onChange={(value) => updateConfiguration("userBaseDn", value)}
          />
          <TextField
            id={`${id}-group-base-dn`}
            label="Group base DN"
            optional
            value={configuration.groupBaseDn ?? ""}
            onChange={(value) =>
              updateConfiguration("groupBaseDn", nullable(value))
            }
          />
          <TextField
            id={`${id}-user-dn-template`}
            label="User DN template"
            optional
            value={configuration.userDnTemplate ?? ""}
            onChange={(value) =>
              updateConfiguration("userDnTemplate", nullable(value))
            }
          />
        </div>
        <FormField
          htmlFor={`${id}-user-filter`}
          label="User search filter"
          hint="Must contain {username} exactly once."
        >
          <Input
            id={`${id}-user-filter`}
            className="ldap-provider-code-input"
            value={configuration.userSearchFilter}
            onChange={(event) =>
              updateConfiguration("userSearchFilter", event.currentTarget.value)
            }
          />
        </FormField>
        <FormField
          htmlFor={`${id}-group-filter`}
          label="Group search filter"
          optional
          hint="Placeholder rules depend on nested-group mode."
        >
          <Input
            id={`${id}-group-filter`}
            className="ldap-provider-code-input"
            value={configuration.groupSearchFilter ?? ""}
            onChange={(event) =>
              updateConfiguration(
                "groupSearchFilter",
                nullable(event.currentTarget.value),
              )
            }
          />
        </FormField>
      </fieldset>

      <fieldset className="ldap-provider-fieldset">
        <legend>Bounded directory work</legend>
        <div className="ldap-provider-form-grid ldap-provider-form-grid--numeric">
          <NumberField
            id={`${id}-page-size`}
            label="Page size"
            min={1}
            max={1000}
            value={configuration.pageSize}
            onChange={(value) => updateConfiguration("pageSize", value)}
          />
          <NumberField
            id={`${id}-max-pages`}
            label="Maximum pages"
            min={1}
            max={1000}
            value={configuration.maxPages}
            onChange={(value) => updateConfiguration("maxPages", value)}
          />
          <NumberField
            id={`${id}-max-entries`}
            label="Maximum entries"
            min={1}
            max={100000}
            value={configuration.maxEntries}
            onChange={(value) => updateConfiguration("maxEntries", value)}
          />
          <NumberField
            id={`${id}-max-bytes`}
            label="Maximum response bytes"
            min={1024}
            max={52428800}
            value={configuration.maxResponseBytes}
            onChange={(value) => updateConfiguration("maxResponseBytes", value)}
          />
          <NumberField
            id={`${id}-max-groups`}
            label="Maximum groups"
            min={1}
            max={10000}
            value={configuration.maxGroups}
            onChange={(value) => updateConfiguration("maxGroups", value)}
          />
        </div>
        <div className="ldap-provider-form-grid">
          <NativeSelectField
            id={`${id}-referral-mode`}
            label="Referral mode"
            value={configuration.referralMode}
            options={[
              ["disabled", "Disabled"],
              ["configured_endpoints", "Configured endpoints only"],
            ]}
            onChange={(value) => {
              const referralMode = value;
              updateDraft({
                configuration: {
                  ...configuration,
                  referralMode,
                  maxReferralHops:
                    referralMode === "disabled"
                      ? 0
                      : Math.max(1, configuration.maxReferralHops),
                },
              });
            }}
          />
          <NumberField
            id={`${id}-referral-hops`}
            label="Maximum referral hops"
            min={configuration.referralMode === "disabled" ? 0 : 1}
            max={3}
            value={configuration.maxReferralHops}
            disabled={configuration.referralMode === "disabled"}
            onChange={(value) => updateConfiguration("maxReferralHops", value)}
          />
          <NativeSelectField
            id={`${id}-nested-mode`}
            label="Nested group mode"
            value={configuration.nestedGroupMode}
            options={[
              ["disabled", "Disabled"],
              ["active_directory", "Active Directory"],
              ["reverse_search", "Reverse search"],
              ["posix_member_uid", "POSIX memberUid"],
            ]}
            onChange={(value) => {
              const nestedGroupMode = value;
              updateDraft({
                configuration: {
                  ...configuration,
                  nestedGroupMode,
                  maxNestedGroupDepth:
                    nestedGroupMode === "disabled"
                      ? 0
                      : Math.max(1, configuration.maxNestedGroupDepth),
                  groupSearchFilter:
                    nestedGroupMode === "disabled"
                      ? null
                      : configuration.groupSearchFilter,
                },
              });
            }}
          />
          <NumberField
            id={`${id}-nested-depth`}
            label="Maximum nested depth"
            min={configuration.nestedGroupMode === "disabled" ? 0 : 1}
            max={20}
            value={configuration.maxNestedGroupDepth}
            disabled={configuration.nestedGroupMode === "disabled"}
            onChange={(value) =>
              updateConfiguration("maxNestedGroupDepth", value)
            }
          />
        </div>
      </fieldset>

      <fieldset className="ldap-provider-fieldset">
        <legend>Attributes and immutable identity</legend>
        <div className="ldap-provider-form-grid">
          <TextField
            id={`${id}-first-name-attribute`}
            label="First-name attribute"
            value={configuration.firstNameAttribute}
            onChange={(value) =>
              updateConfiguration("firstNameAttribute", value)
            }
          />
          <TextField
            id={`${id}-last-name-attribute`}
            label="Last-name attribute"
            value={configuration.lastNameAttribute}
            onChange={(value) =>
              updateConfiguration("lastNameAttribute", value)
            }
          />
          <TextField
            id={`${id}-display-name-attribute`}
            label="Display-name attribute"
            value={configuration.displayNameAttribute}
            onChange={(value) =>
              updateConfiguration("displayNameAttribute", value)
            }
          />
          <TextField
            id={`${id}-username-attribute`}
            label="Username attribute"
            value={configuration.usernameAttribute}
            onChange={(value) =>
              updateConfiguration("usernameAttribute", value)
            }
          />
          <TextField
            id={`${id}-alternate-username-attribute`}
            label="Alternate username attribute"
            optional
            value={configuration.alternateUsernameAttribute ?? ""}
            onChange={(value) =>
              updateConfiguration("alternateUsernameAttribute", nullable(value))
            }
          />
          <TextField
            id={`${id}-email-attribute`}
            label="Email attribute"
            optional
            value={configuration.emailAttribute ?? ""}
            onChange={(value) =>
              updateConfiguration("emailAttribute", nullable(value))
            }
          />
          <TextField
            id={`${id}-subject-attribute`}
            label="Immutable subject attribute"
            value={configuration.immutableSubjectAttribute}
            onChange={(value) =>
              updateConfiguration("immutableSubjectAttribute", value)
            }
          />
          <NativeSelectField
            id={`${id}-subject-format`}
            label="Immutable subject format"
            value={configuration.immutableSubjectFormat}
            options={[
              ["ad_object_guid", "AD objectGUID"],
              ["entry_uuid", "entryUUID"],
              ["utf8_exact", "UTF-8 exact"],
              ["utf8_casefold", "UTF-8 Unicode casefold"],
            ]}
            onChange={(value) =>
              updateConfiguration("immutableSubjectFormat", value)
            }
          />
          <TextField
            id={`${id}-membership-attribute`}
            label="Group membership attribute"
            optional
            value={configuration.groupMembershipAttribute ?? ""}
            onChange={(value) =>
              updateConfiguration("groupMembershipAttribute", nullable(value))
            }
          />
          <TextField
            id={`${id}-member-uid-attribute`}
            label="POSIX memberUid attribute"
            optional
            value={configuration.posixMemberUidAttribute ?? ""}
            onChange={(value) =>
              updateConfiguration("posixMemberUidAttribute", nullable(value))
            }
          />
          <TextField
            id={`${id}-gid-number-attribute`}
            label="POSIX gidNumber attribute"
            optional
            value={configuration.posixGidNumberAttribute ?? ""}
            onChange={(value) =>
              updateConfiguration("posixGidNumberAttribute", nullable(value))
            }
          />
        </div>
      </fieldset>

      <fieldset className="ldap-provider-fieldset">
        <legend>Account status</legend>
        <div className="ldap-provider-form-grid">
          <NativeSelectField
            id={`${id}-account-status-mode`}
            label="Account status mode"
            value={configuration.accountStatusMode}
            options={[
              ["none", "None"],
              ["active_directory_uac", "Active Directory UAC"],
              ["attribute_equals", "Attribute equals"],
            ]}
            onChange={(value) => {
              updateDraft({
                configuration: configurationWithAccountStatus(
                  configuration,
                  value,
                ),
              });
            }}
          />
          <TextField
            id={`${id}-account-status-attribute`}
            label="Account status attribute"
            optional
            disabled={configuration.accountStatusMode === "none"}
            value={configuration.accountStatusAttribute ?? ""}
            onChange={(value) =>
              updateConfiguration("accountStatusAttribute", nullable(value))
            }
          />
          <TextField
            id={`${id}-account-disabled-value`}
            label="Disabled value"
            optional
            disabled={configuration.accountStatusMode !== "attribute_equals"}
            value={configuration.accountDisabledValue ?? ""}
            onChange={(value) =>
              updateConfiguration("accountDisabledValue", nullable(value))
            }
          />
        </div>
      </fieldset>

      <fieldset className="ldap-provider-fieldset ldap-provider-policy-fieldset">
        <legend>
          {policy === "platform_global"
            ? "Platform login policy"
            : "Foundation policy"}
        </legend>
        <p>
          {policy === "platform_global"
            ? "Global LDAP can link only an existing active user after directory authentication and mandatory local TOTP proof. It never creates users or grants super-admin."
            : "These controls remain frozen until their dedicated identity contracts ship."}
        </p>
        <div className="ldap-provider-policy-grid">
          <ReadOnlyPolicy
            label="Account admission"
            value={
              policy === "platform_global"
                ? "Existing identity + TOTP only"
                : "Disabled"
            }
          />
          <ReadOnlyPolicy label="No-match policy" value="Deny" />
          <ReadOnlyPolicy label="Deprovision mode" value="Retain" />
          <ReadOnlyPolicy label="Grace period" value="0 seconds" />
          <ReadOnlyPolicy label="Scheduled sync" value="Unavailable" />
        </div>
      </fieldset>

      <fieldset className="ldap-provider-fieldset">
        <div className="ldap-provider-section-heading">
          <div>
            <legend>Endpoints</legend>
            <p>
              Priority order is explicit; every resolved address is validated by
              deployment egress policy.
            </p>
          </div>
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={addEndpoint}
            disabled={draft.endpoints.length >= 8}
          >
            <Plus aria-hidden="true" /> Add endpoint
          </Button>
        </div>
        <div className="ldap-endpoint-editor-list">
          {draft.endpoints.map((endpoint, index) => (
            <div
              className="ldap-endpoint-editor"
              key={`${index}-${endpoint.priority}`}
            >
              <span className="ldap-endpoint-editor__index" aria-hidden="true">
                {index + 1}
              </span>
              <div className="ldap-provider-form-grid ldap-provider-form-grid--endpoint">
                <NumberField
                  id={`${id}-endpoint-${index}-priority`}
                  label="Priority"
                  min={1}
                  max={8}
                  value={endpoint.priority}
                  onChange={(priority) => updateEndpoint(index, { priority })}
                />
                <TextField
                  id={`${id}-endpoint-${index}-host`}
                  label="Host"
                  value={endpoint.host}
                  onChange={(host) => updateEndpoint(index, { host })}
                />
                <NumberField
                  id={`${id}-endpoint-${index}-port`}
                  label="Port"
                  min={1}
                  max={65535}
                  value={endpoint.port}
                  onChange={(port) => updateEndpoint(index, { port })}
                />
                <NativeSelectField
                  id={`${id}-endpoint-${index}-transport`}
                  label="Transport"
                  value={endpoint.transport}
                  options={[
                    ["ldaps", "LDAPS"],
                    ["starttls", "StartTLS"],
                  ]}
                  onChange={(value) =>
                    updateEndpoint(index, {
                      transport: value,
                      port:
                        value === "ldaps" && endpoint.port === 389
                          ? 636
                          : value === "starttls" && endpoint.port === 636
                            ? 389
                            : endpoint.port,
                    })
                  }
                />
                <TextField
                  id={`${id}-endpoint-${index}-tls-name`}
                  label="TLS server name"
                  value={endpoint.tlsServerName}
                  onChange={(tlsServerName) =>
                    updateEndpoint(index, { tlsServerName })
                  }
                />
              </div>
              <div className="ldap-endpoint-flags">
                <BooleanField
                  id={`${id}-endpoint-${index}-enabled`}
                  label="Endpoint enabled"
                  checked={endpoint.enabled}
                  onChange={(enabled) => updateEndpoint(index, { enabled })}
                />
                <BooleanField
                  id={`${id}-endpoint-${index}-referral`}
                  label="Explicit referral destination"
                  checked={endpoint.referralAllowed}
                  onChange={(referralAllowed) =>
                    updateEndpoint(index, { referralAllowed })
                  }
                />
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  disabled={draft.endpoints.length === 1}
                  onClick={() =>
                    updateDraft({
                      endpoints: draft.endpoints.filter(
                        (_, endpointIndex) => endpointIndex !== index,
                      ),
                    })
                  }
                >
                  <Trash2 aria-hidden="true" /> Remove endpoint
                </Button>
              </div>
            </div>
          ))}
        </div>
      </fieldset>
    </div>
  );
}

function ProviderFacts({
  provider,
}: {
  provider: TenantLdapAuthProviderView;
}): React.JSX.Element {
  return (
    <dl className="ldap-provider-facts">
      <div>
        <dt>Key</dt>
        <dd>
          <code>{provider.key}</code>
        </dd>
      </div>
      <div>
        <dt>Status</dt>
        <dd>
          <ProviderStateBadge provider={provider} />
        </dd>
      </div>
      <div>
        <dt>Template</dt>
        <dd>{templateLabel(provider.template)}</dd>
      </div>
      <div>
        <dt>Version</dt>
        <dd>v{provider.version}</dd>
      </div>
      <div>
        <dt>Bind secret</dt>
        <dd>
          {provider.bindSecretConfigured
            ? `Configured${provider.bindSecretRotatedAt ? ` · rotated ${formatTimestamp(provider.bindSecretRotatedAt)}` : ""}`
            : "Not configured"}
        </dd>
      </div>
      <div>
        <dt>Updated</dt>
        <dd>{formatTimestamp(provider.updatedAt)}</dd>
      </div>
      {provider.description ? (
        <div className="ldap-provider-facts__wide">
          <dt>Description</dt>
          <dd>{provider.description}</dd>
        </div>
      ) : null}
      {provider.archiveReason ? (
        <div className="ldap-provider-facts__wide">
          <dt>Archive reason</dt>
          <dd>{provider.archiveReason}</dd>
        </div>
      ) : null}
    </dl>
  );
}

function EndpointRail({
  endpoints,
}: {
  endpoints: readonly TenantLdapAuthProviderEndpointView[];
}): React.JSX.Element {
  return (
    <section
      className="ldap-endpoint-rail"
      aria-labelledby="ldap-endpoint-rail-title"
    >
      <div className="ldap-provider-section-heading">
        <div>
          <h3 id="ldap-endpoint-rail-title">Endpoint order</h3>
          <p>Each TLS name stays bound to the validated destination.</p>
        </div>
      </div>
      <ol>
        {endpoints.map((endpoint) => (
          <li
            key={`${endpoint.priority}-${endpoint.transport}-${endpoint.host}-${endpoint.port}`}
          >
            <span className="ldap-endpoint-rail__priority">
              P{endpoint.priority}
            </span>
            <span className="ldap-endpoint-rail__line" aria-hidden="true" />
            <div>
              <strong>
                {endpoint.host}:{endpoint.port}
              </strong>
              <small>
                {endpoint.transport.toUpperCase()} · TLS name{" "}
                {endpoint.tlsServerName}
              </small>
            </div>
            <Badge variant={endpoint.enabled ? "default" : "secondary"}>
              {endpoint.enabled ? "Enabled" : "Disabled"}
            </Badge>
            {endpoint.referralAllowed ? (
              <Badge variant="outline">Referral target</Badge>
            ) : null}
          </li>
        ))}
      </ol>
    </section>
  );
}

function DiagnosticPanel({
  diagnostic,
}: {
  diagnostic: TenantLdapAuthProviderDiagnosticView;
}): React.JSX.Element {
  const success = diagnostic.outcome === "success";
  return (
    <Alert
      className={
        success ? "ldap-diagnostic ldap-diagnostic--success" : "ldap-diagnostic"
      }
    >
      {success ? (
        <CheckCircle2 aria-hidden="true" />
      ) : (
        <XCircle aria-hidden="true" />
      )}
      <AlertTitle>{diagnosticCategoryLabel(diagnostic)}</AlertTitle>
      <AlertDescription>
        <span>
          {diagnostic.outcome} · {diagnostic.durationMs} ms
        </span>
        <span>
          {diagnostic.endpointPriority === null
            ? "No endpoint attributed"
            : `Endpoint priority ${diagnostic.endpointPriority}`}
        </span>
        <span>
          {diagnostic.stale
            ? "Historical snapshot; configuration changed"
            : `Completed ${formatTimestamp(diagnostic.completedAt)}`}
        </span>
      </AlertDescription>
    </Alert>
  );
}

function ProviderStateBadge({
  provider,
}: {
  provider: Pick<TenantLdapAuthProviderSummaryView, "archivedAt" | "enabled">;
}): React.JSX.Element {
  if (provider.archivedAt !== null)
    return <Badge variant="secondary">Archived</Badge>;
  return (
    <Badge variant={provider.enabled ? "default" : "outline"}>
      {provider.enabled ? "Enabled" : "Disabled"}
    </Badge>
  );
}

function ValidationSummary({
  errors,
}: {
  errors: readonly string[];
}): React.JSX.Element {
  return (
    <Alert>
      <ShieldAlert aria-hidden="true" />
      <AlertTitle>Review the provider configuration</AlertTitle>
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

function TextField({
  disabled = false,
  id,
  label,
  onChange,
  optional = false,
  value,
}: {
  disabled?: boolean;
  id: string;
  label: string;
  onChange: (value: string) => void;
  optional?: boolean;
  value: string;
}): React.JSX.Element {
  return (
    <FormField htmlFor={id} label={label} optional={optional}>
      <Input
        disabled={disabled}
        id={id}
        value={value}
        onChange={(event) => onChange(event.currentTarget.value)}
      />
    </FormField>
  );
}

function NumberField({
  disabled = false,
  id,
  label,
  max,
  min,
  onChange,
  value,
}: {
  disabled?: boolean;
  id: string;
  label: string;
  max: number;
  min: number;
  onChange: (value: number) => void;
  value: number;
}): React.JSX.Element {
  return (
    <FormField htmlFor={id} label={label}>
      <Input
        disabled={disabled}
        id={id}
        max={max}
        min={min}
        step={1}
        type="number"
        value={String(value)}
        onChange={(event) => onChange(Number(event.currentTarget.value))}
      />
    </FormField>
  );
}

function NativeSelectField<T extends string>({
  id,
  label,
  onChange,
  options,
  value,
}: {
  id: string;
  label: string;
  onChange: (value: T) => void;
  options: readonly (readonly [T, string])[];
  value: T;
}): React.JSX.Element {
  return (
    <FormField htmlFor={id} label={label}>
      <select
        className="ldap-provider-select"
        id={id}
        value={value}
        onChange={(event) => {
          const selected = options.find(
            ([optionValue]) => optionValue === event.currentTarget.value,
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
  hint?: string;
  id: string;
  label: string;
  onChange: (checked: boolean) => void;
}): React.JSX.Element {
  return (
    <div className="ldap-provider-boolean-field">
      <Checkbox
        checked={checked}
        id={id}
        onCheckedChange={(value) => onChange(value === true)}
      />
      <div>
        <Label htmlFor={id}>{label}</Label>
        {hint ? <p>{hint}</p> : null}
      </div>
    </div>
  );
}

function ReadOnlyPolicy({
  label,
  value,
}: {
  label: string;
  value: string;
}): React.JSX.Element {
  return (
    <div className="ldap-provider-readonly-policy">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function LdapProviderSkeleton(): React.JSX.Element {
  return (
    <div
      className="content ldap-provider-list-skeleton"
      aria-label="Loading LDAP providers"
    >
      <span />
      <span />
      <span />
    </div>
  );
}

function LdapDetailSkeleton(): React.JSX.Element {
  return (
    <div
      className="ldap-provider-detail-skeleton"
      aria-label="Loading LDAP provider detail"
    >
      <span />
      <span />
      <span />
    </div>
  );
}

function mergeProviderSummaries(
  current: readonly TenantLdapAuthProviderSummaryView[],
  incoming: readonly TenantLdapAuthProviderSummaryView[],
  tenantId: string,
): readonly TenantLdapAuthProviderSummaryView[] {
  const merged = new Map(current.map((provider) => [provider.id, provider]));
  for (const provider of incoming) {
    if (provider.tenantId !== tenantId) {
      throw new PhaseTwoApiError(
        "The API response did not match the requested tenant projection.",
        undefined,
        { code: tenantProjectionMismatchCode },
      );
    }
    merged.set(provider.id, provider);
  }
  return [...merged.values()].toSorted((left, right) =>
    left.key.localeCompare(right.key),
  );
}

function templateLabel(
  template: TenantLdapAuthProviderSummaryView["template"],
): string {
  return template === "active_directory"
    ? "Active Directory"
    : template === "openldap"
      ? "OpenLDAP"
      : template === "posix"
        ? "POSIX LDAP"
        : "Custom";
}

function nullable(value: string): string | null {
  return value === "" ? null : value;
}

function configurationWithAccountStatus(
  configuration: TenantLdapAuthProviderConfigurationView,
  accountStatusMode: TenantLdapAuthProviderConfigurationView["accountStatusMode"],
): TenantLdapAuthProviderConfigurationView {
  switch (accountStatusMode) {
    case "none":
      return {
        ...configuration,
        accountDisabledValue: null,
        accountStatusAttribute: null,
        accountStatusMode,
      };
    case "active_directory_uac":
      return {
        ...configuration,
        accountDisabledValue: null,
        accountStatusAttribute:
          configuration.accountStatusAttribute ?? "userAccountControl",
        accountStatusMode,
      };
    case "attribute_equals":
      return {
        ...configuration,
        accountDisabledValue: configuration.accountDisabledValue ?? "disabled",
        accountStatusAttribute:
          configuration.accountStatusAttribute ?? "accountStatus",
        accountStatusMode,
      };
    default:
      throw new Error("Unsupported LDAP account-status mode.");
  }
}

function formatTimestamp(value: string): string {
  const parsed = Date.parse(value);
  return Number.isNaN(parsed)
    ? value
    : new Intl.DateTimeFormat(undefined, {
        dateStyle: "medium",
        timeStyle: "short",
      }).format(new Date(parsed));
}

function isAbortError(caught: unknown): boolean {
  return caught instanceof DOMException && caught.name === "AbortError";
}
