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
import { Textarea } from "@periapsis/ui/components/ui/textarea";
import {
  ArrowDown,
  ArrowRight,
  Building2,
  CheckCircle2,
  KeyRound,
  LockKeyhole,
  Plus,
  RefreshCw,
  ShieldCheck,
  ShieldX,
} from "lucide-react";
import { useEffect, useId, useRef, useState } from "react";

import { useSession } from "../auth/session-context";
import { FocusedError } from "../components/focused-error";
import { FormField } from "../components/form-field";
import { readTextField } from "../lib/form-data";
import {
  describePhaseTwoError,
  hasPermission,
  PhaseTwoApiError,
  platformTenantCreatePermission,
  platformTenantAccessPermission,
  platformTenantManagePermission,
  platformTenantReadPermission,
  platformSettingsReadPermission,
  type TenantLifecycleAction,
  type TenantLifecycleReceiptView,
  type TenantView,
} from "../lib/phase-two-types";
import {
  TenantLifecycleClientError,
  TenantLifecycleProvider,
  isMutableTenantLifecycleVersion,
  tenantLifecycleReasonBytes,
  useTenantLifecycle,
  validateTenantLifecycleReason,
} from "../platform/tenant-lifecycle-context";
import { platformOperationsApi } from "../platform/platform-operations-api";

type TenantListState =
  | { kind: "error"; message: string }
  | {
      items: readonly TenantView[];
      kind: "ready";
      nextCursor?: string;
    }
  | { kind: "loading" };

interface LifecycleConfirmation {
  action: TenantLifecycleAction;
  tenant: TenantView;
}

interface AccessConfirmation {
  tenant: TenantView;
}

type TenantCreationDefaults =
  | { kind: "loading"; sessionKey: string }
  | {
      kind: "ready";
      locale: string;
      sessionKey: string;
      timezone: string;
    };

export function PlatformTenantsPage(): React.JSX.Element {
  return (
    <TenantLifecycleProvider>
      <PlatformTenantsContent />
    </TenantLifecycleProvider>
  );
}

function PlatformTenantsContent(): React.JSX.Element {
  const { api, clearSession, refreshMemberships, session } = useSession();
  const lifecycle = useTenantLifecycle();
  const canRead = hasPermission(session, platformTenantReadPermission);
  const canCreate = hasPermission(session, platformTenantCreatePermission);
  const canManage = hasPermission(session, platformTenantManagePermission);
  const canAccess = hasPermission(session, platformTenantAccessPermission);
  const canReadPlatformSettings = hasPermission(
    session,
    platformSettingsReadPermission,
  );
  const [creationDefaults, setCreationDefaults] =
    useState<TenantCreationDefaults>({
      kind: "loading",
      sessionKey: session.id,
    });
  const [listState, setListState] = useState<TenantListState>({
    kind: "loading",
  });
  const [listAttempt, setListAttempt] = useState(0);
  const [isLoadingMore, setIsLoadingMore] = useState(false);
  const [paginationError, setPaginationError] = useState<string | null>(null);
  const [isCreating, setIsCreating] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);
  const [createdName, setCreatedName] = useState<string | null>(null);
  const [lifecycleConfirmation, setLifecycleConfirmation] =
    useState<LifecycleConfirmation | null>(null);
  const [lifecycleReason, setLifecycleReason] = useState("");
  const [lifecycleReasonError, setLifecycleReasonError] = useState<
    string | null
  >(null);
  const [lifecycleError, setLifecycleError] = useState<string | null>(null);
  const [lifecycleConflict, setLifecycleConflict] = useState(false);
  const [lifecycleAnnouncement, setLifecycleAnnouncement] = useState<
    string | null
  >(null);
  const [accessConfirmation, setAccessConfirmation] =
    useState<AccessConfirmation | null>(null);
  const [accessReason, setAccessReason] = useState("");
  const [accessReasonError, setAccessReasonError] = useState<string | null>(
    null,
  );
  const [accessError, setAccessError] = useState<string | null>(null);
  const [accessConflict, setAccessConflict] = useState(false);
  const [accessIdempotencyKey, setAccessIdempotencyKey] = useState("");
  const [isAuthorizingAccess, setIsAuthorizingAccess] = useState(false);
  const [accessAnnouncement, setAccessAnnouncement] = useState<string | null>(
    null,
  );
  const lifecyclePending = lifecycleConfirmation
    ? lifecycle.isPending(lifecycleConfirmation.tenant.id)
    : false;
  const successRef = useRef<HTMLDivElement>(null);
  const lifecycleSuccessRef = useRef<HTMLDivElement>(null);
  const lifecycleReasonRef = useRef<HTMLTextAreaElement>(null);
  const accessSuccessRef = useRef<HTMLDivElement>(null);
  const accessReasonRef = useRef<HTMLTextAreaElement>(null);
  const sessionIdRef = useRef(session.id);
  sessionIdRef.current = session.id;
  const id = useId();

  useEffect(() => {
    setIsLoadingMore(false);
    setPaginationError(null);
    setIsCreating(false);
    setCreateError(null);
    setCreatedName(null);
    dismissLifecycleConfirmation();
    setLifecycleAnnouncement(null);
    dismissAccessConfirmation();
    setAccessAnnouncement(null);
  }, [session.id]);

  useEffect(() => {
    const sessionKey = session.id;
    const fallback = (): void =>
      setCreationDefaults({
        kind: "ready",
        locale: "en",
        sessionKey,
        timezone: "UTC",
      });
    setCreationDefaults({ kind: "loading", sessionKey });
    if (!canCreate || !canReadPlatformSettings) {
      fallback();
      return undefined;
    }

    const controller = new AbortController();
    void platformOperationsApi
      .getSettings({ signal: controller.signal })
      .then((settings) => {
        if (!controller.signal.aborted) {
          setCreationDefaults({
            kind: "ready",
            locale: settings.defaultLocale,
            sessionKey,
            timezone: settings.defaultTimezone,
          });
        }
      })
      .catch(() => {
        if (!controller.signal.aborted) fallback();
      });
    return () => controller.abort();
  }, [canCreate, canReadPlatformSettings, session.id]);

  useEffect(() => {
    if (!canManage) dismissLifecycleConfirmation();
  }, [canManage]);

  useEffect(() => {
    if (!canAccess) dismissAccessConfirmation();
  }, [canAccess]);

  useEffect(() => {
    if (!canRead) {
      return undefined;
    }
    let cancelled = false;
    setListState({ kind: "loading" });

    void api
      .listTenants()
      .then((page) => {
        if (!cancelled) {
          setListState({
            kind: "ready",
            items: page.items,
            ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
          });
        }
      })
      .catch((caught: unknown) => {
        if (cancelled) {
          return;
        }
        if (caught instanceof PhaseTwoApiError && caught.status === 401) {
          clearSession(session.id);
          return;
        }
        setListState({
          kind: "error",
          message: describePhaseTwoError(
            caught,
            "The platform tenant list could not be loaded.",
          ),
        });
      });

    return () => {
      cancelled = true;
    };
  }, [api, canRead, clearSession, listAttempt, session.id]);

  async function loadMore(): Promise<void> {
    if (listState.kind !== "ready" || !listState.nextCursor || isLoadingMore) {
      return;
    }
    const requestedCursor = listState.nextCursor;
    const requestedSessionId = session.id;
    setIsLoadingMore(true);
    setPaginationError(null);
    try {
      const page = await api.listTenants(requestedCursor);
      if (sessionIdRef.current !== requestedSessionId) {
        return;
      }
      if (page.nextCursor === requestedCursor) {
        throw new Error("The tenant cursor did not advance.");
      }
      setListState((current) =>
        current.kind === "ready" && current.nextCursor === requestedCursor
          ? {
              kind: "ready",
              items: mergeTenants(current.items, page.items),
              ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
            }
          : current,
      );
    } catch (caught) {
      if (sessionIdRef.current !== requestedSessionId) {
        return;
      }
      if (caught instanceof PhaseTwoApiError && caught.status === 401) {
        clearSession(requestedSessionId);
        return;
      }
      setPaginationError(
        describePhaseTwoError(
          caught,
          "The next page of tenants could not be loaded.",
        ),
      );
    } finally {
      if (sessionIdRef.current === requestedSessionId) {
        setIsLoadingMore(false);
      }
    }
  }

  async function createTenant(
    event: React.FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault();
    const form = event.currentTarget;
    const fields = new FormData(form);
    setCreateError(null);
    setCreatedName(null);
    setIsCreating(true);
    const expectedSessionId = session.id;

    try {
      const tenant = await api.createTenant(session.csrfToken, {
        locale: readTextField(fields, "locale").trim(),
        name: readTextField(fields, "name").trim(),
        slug: readTextField(fields, "slug").trim().toLowerCase(),
        timezone: readTextField(fields, "timezone").trim(),
      });
      if (sessionIdRef.current !== expectedSessionId) {
        return;
      }
      form.reset();
      setCreatedName(tenant.name);
      refreshMemberships();
      setListState((current) =>
        current.kind === "ready"
          ? {
              ...current,
              items: mergeTenants([tenant], current.items),
            }
          : current,
      );
      requestAnimationFrame(() => successRef.current?.focus());
    } catch (caught) {
      if (sessionIdRef.current !== expectedSessionId) {
        return;
      }
      if (caught instanceof PhaseTwoApiError && caught.status === 401) {
        clearSession(expectedSessionId);
        return;
      }
      setCreateError(
        describePhaseTwoError(
          caught,
          "The tenant was not created. Review the fields and try again.",
        ),
      );
    } finally {
      if (sessionIdRef.current === expectedSessionId) {
        setIsCreating(false);
      }
    }
  }

  function openLifecycleConfirmation(tenant: TenantView): void {
    if (!canManage || !isMutableLifecycleTenant(tenant)) return;
    setLifecycleConfirmation({
      action: tenant.status === "active" ? "suspend" : "reactivate",
      tenant,
    });
    setLifecycleReason("");
    setLifecycleReasonError(null);
    setLifecycleError(null);
    setLifecycleConflict(false);
  }

  function dismissLifecycleConfirmation(): void {
    setLifecycleConfirmation(null);
    setLifecycleReason("");
    setLifecycleReasonError(null);
    setLifecycleError(null);
    setLifecycleConflict(false);
  }

  async function changeTenantLifecycle(
    event: React.FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault();
    if (!lifecycleConfirmation || !canManage) return;
    const reasonError = validateTenantLifecycleReason(lifecycleReason);
    if (reasonError) {
      setLifecycleReasonError(reasonError);
      requestAnimationFrame(() => lifecycleReasonRef.current?.focus());
      return;
    }
    const currentTenant =
      listState.kind === "ready"
        ? listState.items.find(
            (tenant) => tenant.id === lifecycleConfirmation.tenant.id,
          )
        : undefined;
    if (
      !currentTenant ||
      currentTenant.status !== lifecycleConfirmation.tenant.status ||
      currentTenant.version !== lifecycleConfirmation.tenant.version
    ) {
      setLifecycleConflict(true);
      setLifecycleError(staleTenantLifecycleMessage);
      return;
    }

    setLifecycleReasonError(null);
    setLifecycleError(null);
    setLifecycleConflict(false);
    try {
      const receipt = await lifecycle.transition(
        currentTenant,
        lifecycleConfirmation.action,
        lifecycleReason,
      );
      if (!receipt) return;
      applyLifecycleReceipt(receipt);
      const actionLabel =
        lifecycleConfirmation.action === "suspend"
          ? "suspended"
          : "reactivated";
      setLifecycleAnnouncement(
        `${currentTenant.name} was ${actionLabel}. The inventory now shows revision ${receipt.version}.`,
      );
      dismissLifecycleConfirmation();
      requestAnimationFrame(() => lifecycleSuccessRef.current?.focus());
    } catch (caught) {
      if (caught instanceof PhaseTwoApiError && caught.status === 412) {
        setLifecycleConflict(true);
        setLifecycleError(staleTenantLifecycleMessage);
        return;
      }
      setLifecycleError(
        caught instanceof TenantLifecycleClientError
          ? caught.message
          : describePhaseTwoError(
              caught,
              "The tenant lifecycle state was not changed.",
            ),
      );
    }
  }

  function applyLifecycleReceipt(receipt: TenantLifecycleReceiptView): void {
    setListState((current) =>
      current.kind === "ready"
        ? {
            ...current,
            items: current.items.map((tenant) =>
              tenant.id === receipt.tenantId
                ? {
                    ...tenant,
                    status: receipt.status,
                    updatedAt: receipt.updatedAt,
                    version: receipt.version,
                  }
                : tenant,
            ),
          }
        : current,
    );
  }

  function reloadTenantInventory(): void {
    dismissLifecycleConfirmation();
    setLifecycleAnnouncement(null);
    setListAttempt((attempt) => attempt + 1);
  }

  function openAccessConfirmation(tenant: TenantView): void {
    if (
      !canAccess ||
      tenant.status !== "active" ||
      !isMutableLifecycleTenant(tenant) ||
      tenant.id === session.activeTenantId
    ) {
      return;
    }
    setAccessConfirmation({ tenant });
    setAccessReason("");
    setAccessReasonError(null);
    setAccessError(null);
    setAccessConflict(false);
    setAccessIdempotencyKey(`tenant-access-${globalThis.crypto.randomUUID()}`);
  }

  function dismissAccessConfirmation(): void {
    setAccessConfirmation(null);
    setAccessReason("");
    setAccessReasonError(null);
    setAccessError(null);
    setAccessConflict(false);
    setAccessIdempotencyKey("");
    setIsAuthorizingAccess(false);
  }

  async function authorizeTenantAccess(
    event: React.FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault();
    if (!accessConfirmation || !canAccess || isAuthorizingAccess) return;
    const reasonError = validateTenantLifecycleReason(accessReason);
    if (reasonError) {
      setAccessReasonError(reasonError);
      requestAnimationFrame(() => accessReasonRef.current?.focus());
      return;
    }
    const currentTenant =
      listState.kind === "ready"
        ? listState.items.find(
            (tenant) => tenant.id === accessConfirmation.tenant.id,
          )
        : undefined;
    if (
      !currentTenant ||
      currentTenant.status !== "active" ||
      currentTenant.version !== accessConfirmation.tenant.version ||
      !isMutableLifecycleTenant(currentTenant) ||
      !/^[A-Za-z0-9._~-]{16,128}$/.test(accessIdempotencyKey)
    ) {
      setAccessConflict(true);
      setAccessError(staleTenantAccessMessage);
      return;
    }

    const expectedSessionId = session.id;
    setAccessReasonError(null);
    setAccessError(null);
    setAccessConflict(false);
    setIsAuthorizingAccess(true);
    try {
      const receipt = await api.authorizePlatformTenantAccess(
        session.csrfToken,
        currentTenant.id,
        `"v${currentTenant.version}"`,
        accessIdempotencyKey,
        { expectedVersion: currentTenant.version, reason: accessReason },
      );
      if (sessionIdRef.current !== expectedSessionId) return;
      if (
        receipt.tenantId !== currentTenant.id ||
        receipt.userId !== session.user.id ||
        receipt.tenantVersion !== currentTenant.version
      ) {
        throw new PhaseTwoApiError(
          "The tenant-access receipt was inconsistent.",
        );
      }
      refreshMemberships();
      setAccessAnnouncement(
        `${currentTenant.name} access is authorized. Select it in the tenant switcher to perform the separately audited context change.`,
      );
      dismissAccessConfirmation();
      requestAnimationFrame(() => accessSuccessRef.current?.focus());
    } catch (caught) {
      if (sessionIdRef.current !== expectedSessionId) return;
      if (caught instanceof PhaseTwoApiError && caught.status === 401) {
        clearSession(expectedSessionId);
        return;
      }
      if (caught instanceof PhaseTwoApiError && caught.status === 412) {
        setAccessConflict(true);
        setAccessError(staleTenantAccessMessage);
        return;
      }
      setAccessError(
        caught instanceof PhaseTwoApiError && caught.status === 409
          ? "Access was not added. This administrator already has a tenant membership, or the retry key belongs to a different request."
          : describePhaseTwoError(
              caught,
              "Access was not authorized. Confirm that this session has fresh MFA and try again.",
            ),
      );
    } finally {
      if (sessionIdRef.current === expectedSessionId) {
        setIsAuthorizingAccess(false);
      }
    }
  }

  function reloadAfterAccessConflict(): void {
    dismissAccessConfirmation();
    setAccessAnnouncement(null);
    setListAttempt((attempt) => attempt + 1);
  }

  if (!canRead) {
    return (
      <div className="content content--narrow">
        <section className="page-heading" aria-labelledby="tenant-denied-title">
          <p className="section-label">Platform administration</p>
          <h1 id="tenant-denied-title">Tenant inventory is not available.</h1>
          <p>
            The current session did not return the explicit platform tenant read
            permission. The API remains the authorization boundary.
          </p>
        </section>
        <Alert variant="destructive">
          <ShieldX aria-hidden="true" />
          <AlertTitle>Permission not returned</AlertTitle>
          <AlertDescription>
            Ask a platform administrator to review this identity. Tenant
            membership alone does not grant platform administration.
          </AlertDescription>
        </Alert>
      </div>
    );
  }

  return (
    <div className="content tenant-page">
      <section className="page-heading" aria-labelledby="tenant-page-title">
        <div>
          <p className="section-label">Platform administration</p>
          <h1 id="tenant-page-title">Tenant inventory</h1>
          <p>
            Create isolation boundaries and inspect their lifecycle state. The
            API creates an audited tenant-admin membership for the creator. The
            switcher refreshes only from the server membership endpoint.
          </p>
        </div>
        <Badge variant="outline">
          <Building2 aria-hidden="true" /> Server-authorized view
        </Badge>
      </section>

      {canCreate ? (
        <Card className="tenant-create-card">
          <CardHeader>
            <CardTitle>Create tenant</CardTitle>
            <CardDescription>
              This operation uses the current in-memory CSRF value and is
              independently authorized and audited by the API.
            </CardDescription>
          </CardHeader>
          <CardContent>
            {creationDefaults.kind === "loading" ||
            creationDefaults.sessionKey !== session.id ? (
              <p role="status">Loading platform tenant defaults…</p>
            ) : (
              <form
                key={creationDefaults.sessionKey}
                className="tenant-create-form"
                onSubmit={createTenant}
              >
                {createError ? <FocusedError message={createError} /> : null}
                {createdName ? (
                  <Alert
                    ref={successRef}
                    tabIndex={-1}
                    className="success-alert"
                  >
                    <CheckCircle2 aria-hidden="true" />
                    <AlertTitle>Tenant created</AlertTitle>
                    <AlertDescription>
                      {createdName} is now in the platform inventory. Its
                      server-created membership is being refreshed separately.
                    </AlertDescription>
                  </Alert>
                ) : null}
                <div className="tenant-create-grid">
                  <FormField htmlFor={`${id}-tenant-name`} label="Tenant name">
                    <Input
                      id={`${id}-tenant-name`}
                      name="name"
                      autoComplete="organization"
                      required
                      maxLength={160}
                      disabled={isCreating}
                    />
                  </FormField>
                  <FormField
                    htmlFor={`${id}-tenant-slug`}
                    label="Tenant slug"
                    hint="Lowercase DNS label, for example acme-soc."
                  >
                    <Input
                      id={`${id}-tenant-slug`}
                      name="slug"
                      autoCapitalize="none"
                      autoCorrect="off"
                      pattern="[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
                      required
                      maxLength={63}
                      disabled={isCreating}
                      aria-describedby={`${id}-tenant-slug-hint`}
                    />
                  </FormField>
                  <FormField
                    htmlFor={`${id}-tenant-timezone`}
                    label="IANA time zone"
                    hint="Use a canonical region such as Europe/Rome or UTC."
                  >
                    <Input
                      id={`${id}-tenant-timezone`}
                      name="timezone"
                      defaultValue={creationDefaults.timezone}
                      required
                      maxLength={64}
                      disabled={isCreating}
                      aria-describedby={`${id}-tenant-timezone-hint`}
                    />
                  </FormField>
                  <FormField
                    htmlFor={`${id}-tenant-locale`}
                    label="Locale"
                    hint="BCP 47 language tag, for example en or it-IT."
                  >
                    <Input
                      id={`${id}-tenant-locale`}
                      name="locale"
                      defaultValue={creationDefaults.locale}
                      required
                      maxLength={35}
                      pattern="[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*"
                      disabled={isCreating}
                      aria-describedby={`${id}-tenant-locale-hint`}
                    />
                  </FormField>
                </div>
                <Button type="submit" disabled={isCreating}>
                  <Plus aria-hidden="true" />
                  {isCreating ? "Creating tenant…" : "Create tenant"}
                </Button>
              </form>
            )}
          </CardContent>
        </Card>
      ) : null}

      <section className="tenant-inventory" aria-labelledby="inventory-title">
        <div className="section-heading">
          <div>
            <p className="section-label">Isolation boundaries</p>
            <h2 id="inventory-title">Platform tenants</h2>
          </div>
          {listState.kind === "error" ? (
            <Button
              type="button"
              variant="outline"
              onClick={() => setListAttempt((attempt) => attempt + 1)}
            >
              <RefreshCw aria-hidden="true" /> Retry
            </Button>
          ) : null}
        </div>

        {!canManage ? (
          <Alert className="tenant-lifecycle-permission">
            <LockKeyhole aria-hidden="true" />
            <AlertTitle>Lifecycle controls are read-only</AlertTitle>
            <AlertDescription>
              This session did not return platform.tenant.manage. The API
              independently authorizes every lifecycle request.
            </AlertDescription>
          </Alert>
        ) : null}
        {!canAccess ? (
          <Alert className="tenant-lifecycle-permission">
            <KeyRound aria-hidden="true" />
            <AlertTitle>Elevated tenant access is unavailable</AlertTitle>
            <AlertDescription>
              This session did not return platform.tenant.access. Tenant data
              remains inaccessible unless an explicit ordinary membership is
              created by the independently authorized API command.
            </AlertDescription>
          </Alert>
        ) : null}
        {lifecycleAnnouncement ? (
          <Alert
            ref={lifecycleSuccessRef}
            tabIndex={-1}
            className="success-alert tenant-lifecycle-success"
          >
            <CheckCircle2 aria-hidden="true" />
            <AlertTitle>Lifecycle state changed</AlertTitle>
            <AlertDescription>{lifecycleAnnouncement}</AlertDescription>
          </Alert>
        ) : null}
        {accessAnnouncement ? (
          <Alert
            ref={accessSuccessRef}
            tabIndex={-1}
            className="success-alert tenant-lifecycle-success"
          >
            <CheckCircle2 aria-hidden="true" />
            <AlertTitle>Tenant access authorized</AlertTitle>
            <AlertDescription>{accessAnnouncement}</AlertDescription>
          </Alert>
        ) : null}

        {listState.kind === "loading" ? <TenantListSkeleton /> : null}
        {listState.kind === "error" ? (
          <FocusedError message={listState.message} />
        ) : null}
        {paginationError ? (
          <FocusedError
            message={paginationError}
            title="More tenants could not be loaded"
          />
        ) : null}
        {listState.kind === "ready" && listState.items.length === 0 ? (
          <div className="tenant-empty">
            <Building2 aria-hidden="true" />
            <h3>No tenants yet</h3>
            <p>
              Create the first customer isolation boundary when its ownership,
              time zone, and locale are known.
            </p>
          </div>
        ) : null}
        {listState.kind === "ready" && listState.items.length > 0 ? (
          <div className="tenant-table-wrap">
            <table className="tenant-table">
              <caption className="sr-only">
                Platform tenant isolation boundaries
              </caption>
              <thead>
                <tr>
                  <th scope="col">Tenant</th>
                  <th scope="col">Status</th>
                  <th scope="col">Time zone</th>
                  <th scope="col">Locale</th>
                  <th scope="col">Created</th>
                  {canManage ? <th scope="col">Lifecycle action</th> : null}
                  {canAccess ? <th scope="col">Explicit access</th> : null}
                </tr>
              </thead>
              <tbody>
                {listState.items.map((tenant) => {
                  const mutable = isMutableLifecycleTenant(tenant);
                  const pending = lifecycle.isPending(tenant.id);
                  const action =
                    tenant.status === "active" ? "suspend" : "reactivate";
                  return (
                    <tr key={tenant.id} data-lifecycle-state={tenant.status}>
                      <th scope="row">
                        <strong>{tenant.name}</strong>
                        <small>{tenant.slug}</small>
                        {tenant.id === session.activeTenantId ? (
                          <Badge variant="outline">Active context</Badge>
                        ) : null}
                      </th>
                      <td>
                        <Badge
                          variant={
                            tenant.status === "active" ? "secondary" : "outline"
                          }
                        >
                          {formatStatus(tenant.status)}
                        </Badge>
                        <small className="tenant-lifecycle-revision">
                          {tenant.version === undefined
                            ? "Revision unavailable"
                            : `Revision ${tenant.version}`}
                        </small>
                      </td>
                      <td>{tenant.timezone}</td>
                      <td>{tenant.locale}</td>
                      <td>{formatDate(tenant.createdAt)}</td>
                      {canManage ? (
                        <td className="tenant-lifecycle-action">
                          <Button
                            type="button"
                            size="sm"
                            variant={
                              tenant.status === "active"
                                ? "destructive"
                                : "outline"
                            }
                            disabled={!mutable || pending}
                            aria-describedby={
                              mutable
                                ? undefined
                                : `${id}-tenant-lifecycle-unavailable-${tenant.id}`
                            }
                            aria-label={`${formatLifecycleAction(action)} ${tenant.name}`}
                            onClick={() => openLifecycleConfirmation(tenant)}
                          >
                            {pending
                              ? "Changing state…"
                              : formatLifecycleAction(action)}
                          </Button>
                          {!mutable ? (
                            <small
                              id={`${id}-tenant-lifecycle-unavailable-${tenant.id}`}
                            >
                              {tenant.version === undefined
                                ? "Current revision is not available."
                                : "This revision can no longer advance."}
                            </small>
                          ) : null}
                        </td>
                      ) : null}
                      {canAccess ? (
                        <td className="tenant-lifecycle-action">
                          <Button
                            type="button"
                            size="sm"
                            variant="outline"
                            disabled={
                              tenant.status !== "active" ||
                              !mutable ||
                              isAuthorizingAccess ||
                              tenant.id === session.activeTenantId
                            }
                            aria-label={`Authorize explicit access to ${tenant.name}`}
                            onClick={() => openAccessConfirmation(tenant)}
                          >
                            <KeyRound aria-hidden="true" />
                            {tenant.id === session.activeTenantId
                              ? "Current tenant"
                              : "Authorize access"}
                          </Button>
                          {tenant.status !== "active" ? (
                            <small>Only active tenants can be entered.</small>
                          ) : tenant.id === session.activeTenantId ? (
                            <small>The active tenant is already visible.</small>
                          ) : null}
                        </td>
                      ) : null}
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : null}
        {listState.kind === "ready" && listState.nextCursor ? (
          <Button
            type="button"
            variant="outline"
            onClick={() => void loadMore()}
            disabled={isLoadingMore}
          >
            <ArrowDown aria-hidden="true" />
            {isLoadingMore ? "Loading tenants…" : "Load more tenants"}
          </Button>
        ) : null}
      </section>

      <Dialog
        open={lifecycleConfirmation !== null}
        onOpenChange={(open) => {
          if (!open && lifecycleConfirmation && !lifecyclePending) {
            dismissLifecycleConfirmation();
          }
        }}
      >
        {lifecycleConfirmation ? (
          <DialogContent
            className="tenant-lifecycle-dialog"
            showCloseButton={!lifecyclePending}
          >
            <DialogHeader>
              <p className="section-label">Lifecycle confirmation</p>
              <DialogTitle>
                {formatLifecycleAction(lifecycleConfirmation.action)}{" "}
                {lifecycleConfirmation.tenant.name}
              </DialogTitle>
              <DialogDescription>
                {lifecycleConfirmation.action === "suspend"
                  ? "Suspension blocks the tenant from active platform use until an authorized operator reactivates it."
                  : "Reactivation restores the tenant to active platform use after the cause of suspension has been resolved."}
              </DialogDescription>
            </DialogHeader>

            <div
              className="tenant-lifecycle-boundary"
              data-action={lifecycleConfirmation.action}
              role="group"
              aria-label={`Lifecycle state changes from ${lifecycleConfirmation.tenant.status} to ${lifecycleTarget(lifecycleConfirmation.action)}`}
            >
              <div>
                <span>Current</span>
                <strong>
                  {formatStatus(lifecycleConfirmation.tenant.status)}
                </strong>
              </div>
              <ArrowRight aria-hidden="true" />
              <div>
                <span>After confirmation</span>
                <strong>
                  {formatStatus(lifecycleTarget(lifecycleConfirmation.action))}
                </strong>
              </div>
              <p>
                <ShieldCheck aria-hidden="true" /> Exact boundary · revision{" "}
                {lifecycleConfirmation.tenant.version}
              </p>
            </div>

            <form
              className="tenant-lifecycle-form"
              onSubmit={changeTenantLifecycle}
              noValidate
            >
              {lifecycleError ? (
                <FocusedError
                  title={
                    lifecycleConflict
                      ? "Tenant state changed"
                      : "Lifecycle change failed"
                  }
                  message={lifecycleError}
                />
              ) : null}
              <FormField
                htmlFor={`${id}-tenant-lifecycle-reason`}
                label="Administrative reason"
                hint={`${tenantLifecycleReasonBytes(lifecycleReason)} of 2048 UTF-8 bytes. Retained in the audit trail; do not include secrets, tokens, credentials, or customer data.`}
                {...(lifecycleReasonError
                  ? { error: lifecycleReasonError }
                  : {})}
              >
                <Textarea
                  ref={lifecycleReasonRef}
                  id={`${id}-tenant-lifecycle-reason`}
                  name="reason"
                  value={lifecycleReason}
                  required
                  maxLength={2048}
                  autoFocus
                  disabled={lifecyclePending}
                  aria-invalid={lifecycleReasonError ? "true" : undefined}
                  aria-describedby={`${id}-tenant-lifecycle-reason-${lifecycleReasonError ? "error" : "hint"}`}
                  onChange={(event) => {
                    setLifecycleReason(event.currentTarget.value);
                    setLifecycleReasonError(null);
                    if (!lifecycleConflict) setLifecycleError(null);
                  }}
                />
              </FormField>
              <DialogFooter>
                {lifecycleConflict ? (
                  <Button
                    type="button"
                    variant="outline"
                    onClick={reloadTenantInventory}
                  >
                    <RefreshCw aria-hidden="true" /> Reload tenant inventory
                  </Button>
                ) : (
                  <Button
                    type="button"
                    variant="outline"
                    disabled={lifecyclePending}
                    onClick={dismissLifecycleConfirmation}
                  >
                    Cancel
                  </Button>
                )}
                <Button
                  type="submit"
                  variant={
                    lifecycleConfirmation.action === "suspend"
                      ? "destructive"
                      : "default"
                  }
                  disabled={lifecyclePending || lifecycleConflict}
                >
                  {lifecyclePending
                    ? "Changing lifecycle state…"
                    : `${formatLifecycleAction(lifecycleConfirmation.action)} tenant`}
                </Button>
              </DialogFooter>
            </form>
          </DialogContent>
        ) : null}
      </Dialog>

      <Dialog
        open={accessConfirmation !== null}
        onOpenChange={(open) => {
          if (!open && accessConfirmation && !isAuthorizingAccess) {
            dismissAccessConfirmation();
          }
        }}
      >
        {accessConfirmation ? (
          <DialogContent
            className="tenant-lifecycle-dialog"
            showCloseButton={!isAuthorizingAccess}
          >
            <DialogHeader>
              <p className="section-label">Explicit elevated access</p>
              <DialogTitle>
                Authorize access to {accessConfirmation.tenant.name}
              </DialogTitle>
              <DialogDescription>
                This creates a real tenant-admin membership for your user; it
                does not bypass row-level security. A fresh MFA proof within 15
                minutes is required by the database.
              </DialogDescription>
            </DialogHeader>

            <div
              className="tenant-lifecycle-boundary"
              role="group"
              aria-label={`Explicit tenant access at revision ${accessConfirmation.tenant.version}`}
            >
              <div>
                <span>Before</span>
                <strong>No implicit access</strong>
              </div>
              <ArrowRight aria-hidden="true" />
              <div>
                <span>After confirmation</span>
                <strong>Tenant administrator</strong>
              </div>
              <p>
                <ShieldCheck aria-hidden="true" /> Platform and tenant audit ·
                revision {accessConfirmation.tenant.version}
              </p>
            </div>

            <Alert>
              <LockKeyhole aria-hidden="true" />
              <AlertTitle>Context does not switch automatically</AlertTitle>
              <AlertDescription>
                After authorization, choose this tenant in the tenant switcher.
                That separate context change is also checked and audited.
              </AlertDescription>
            </Alert>

            <form
              className="tenant-lifecycle-form"
              onSubmit={authorizeTenantAccess}
              noValidate
            >
              {accessError ? (
                <FocusedError
                  title={
                    accessConflict
                      ? "Tenant state changed"
                      : "Tenant access failed"
                  }
                  message={accessError}
                />
              ) : null}
              <FormField
                htmlFor={`${id}-tenant-access-reason`}
                label="Access justification"
                hint={`${tenantLifecycleReasonBytes(accessReason)} of 2048 UTF-8 bytes. Stored in both audit streams; do not include secrets, credentials, or customer data.`}
                {...(accessReasonError ? { error: accessReasonError } : {})}
              >
                <Textarea
                  ref={accessReasonRef}
                  id={`${id}-tenant-access-reason`}
                  name="reason"
                  value={accessReason}
                  required
                  maxLength={2048}
                  autoFocus
                  disabled={isAuthorizingAccess}
                  aria-invalid={accessReasonError ? "true" : undefined}
                  aria-describedby={`${id}-tenant-access-reason-${accessReasonError ? "error" : "hint"}`}
                  onChange={(event) => {
                    setAccessReason(event.currentTarget.value);
                    setAccessReasonError(null);
                    if (!accessConflict) setAccessError(null);
                  }}
                />
              </FormField>
              <DialogFooter>
                {accessConflict ? (
                  <Button
                    type="button"
                    variant="outline"
                    onClick={reloadAfterAccessConflict}
                  >
                    <RefreshCw aria-hidden="true" /> Reload tenant inventory
                  </Button>
                ) : (
                  <Button
                    type="button"
                    variant="outline"
                    disabled={isAuthorizingAccess}
                    onClick={dismissAccessConfirmation}
                  >
                    Cancel
                  </Button>
                )}
                <Button
                  type="submit"
                  disabled={isAuthorizingAccess || accessConflict}
                >
                  <KeyRound aria-hidden="true" />
                  {isAuthorizingAccess
                    ? "Authorizing access…"
                    : "Create tenant-admin membership"}
                </Button>
              </DialogFooter>
            </form>
          </DialogContent>
        ) : null}
      </Dialog>
    </div>
  );
}

function TenantListSkeleton(): React.JSX.Element {
  return (
    <div className="tenant-list-skeleton" aria-label="Loading platform tenants">
      <span />
      <span />
      <span />
    </div>
  );
}

function mergeTenants(
  first: readonly TenantView[],
  second: readonly TenantView[],
): readonly TenantView[] {
  const tenants = new Map<string, TenantView>();
  for (const tenant of [...first, ...second]) {
    tenants.set(tenant.id, tenant);
  }
  return [...tenants.values()];
}

function formatDate(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.valueOf())) {
    return "Unavailable";
  }
  return new Intl.DateTimeFormat(undefined, {
    day: "2-digit",
    month: "short",
    year: "numeric",
  }).format(date);
}

function formatStatus(value: string): string {
  const label = value.replaceAll("_", " ");
  return label.charAt(0).toUpperCase() + label.slice(1);
}

const staleTenantLifecycleMessage =
  "This confirmation used an older tenant state. Reload the inventory and review the change again.";

const staleTenantAccessMessage =
  "This confirmation used an older tenant or access state. Reload the inventory and review the explicit access boundary again.";

function isMutableLifecycleTenant(
  tenant: TenantView,
): tenant is TenantView & { version: number } {
  return isMutableTenantLifecycleVersion(tenant.version);
}

function lifecycleTarget(action: TenantLifecycleAction): TenantView["status"] {
  return action === "suspend" ? "suspended" : "active";
}

function formatLifecycleAction(action: TenantLifecycleAction): string {
  return action === "suspend" ? "Suspend" : "Reactivate";
}
