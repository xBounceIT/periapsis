import { Badge } from "@periapsis/ui/components/ui/badge";
import { Button } from "@periapsis/ui/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@periapsis/ui/components/ui/card";
import { Separator } from "@periapsis/ui/components/ui/separator";
import { useQuery } from "@tanstack/react-query";
import {
  Activity,
  ArrowUpRight,
  BellRing,
  Bot,
  Braces,
  BriefcaseBusiness,
  Building2,
  CircleUserRound,
  Clock3,
  ContactRound,
  FileClock,
  FileJson2,
  FileSpreadsheet,
  Fingerprint,
  Gauge,
  GitBranch,
  Hash,
  Inbox,
  KeyRound,
  Laptop,
  LifeBuoy,
  LogOut,
  MailCheck,
  Network,
  Orbit,
  Palette,
  RadioTower,
  RefreshCw,
  Search,
  Send,
  ServerCog,
  Shield,
  ShieldCheck,
  Users,
  UsersRound,
} from "lucide-react";
import {
  useCallback,
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
  type CSSProperties,
} from "react";
import { NavLink, Outlet, useLocation, useNavigate } from "react-router";
import { appRouteTitle } from "./app-model";

import {
  platformAuditPermission,
  platformAuditRouteDescriptor,
  tenantAuditPermission,
  tenantAuditRouteDescriptor,
} from "./audit/model";
import { mfaSecurityRouteDescriptor } from "./auth/mfa/model";
import { PlatformOperatorTeamCoordinatorProvider } from "./auth/platform-operator-team-coordinator";
import { useSession } from "./auth/session-context";
import {
  TenantAuthorityProvider,
  useTenantAuthority,
} from "./auth/tenant-authority-context";
import { FocusedError } from "./components/focused-error";
import { StatusPanel } from "./components/status-panel";
import { TenantSwitcher } from "./components/tenant-switcher";
import { contactAdministrationRouteDescriptor } from "./contacts/model";
import { customFieldImportRouteDescriptor } from "./customfields/custom-field-import-model";
import { customFieldAdministrationRouteDescriptor } from "./customfields/model";
import { tenantFederationRouteDescriptor } from "./federation/model";
import {
  describePhaseTwoError,
  hasPermission,
  PhaseTwoApiError,
  platformIdentityAccountReadPermission,
  platformIdentityBindingReadPermission,
  platformIdentityProviderReadPermission,
  platformOperatorTeamReadPermission,
  platformSettingsReadPermission,
  platformTenantReadPermission,
} from "./lib/phase-two-types";
import { loadSystemStatus } from "./lib/system-status";
import { useTenantDateTime } from "./lib/tenant-date-time";
import { TenantDateTimeProvider } from "./lib/tenant-date-time-context";
import {
  platformMfaPolicyReadPermission,
  platformMfaPolicyRouteDescriptor,
  tenantMfaPolicyReadPermission,
  tenantMfaPolicyRouteDescriptor,
} from "./mfapolicy/model";
import { notificationInboxRouteDescriptor } from "./notifications/inbox-model";
import {
  platformNotificationPermission,
  platformSmtpRouteDescriptor,
  tenantNotificationPermission,
  tenantNotificationRouteDescriptor,
} from "./notifications/model";
import { platformAuthProviderRouteDescriptor } from "./pages/platform-auth-provider-model";
import { platformLocalAccountRouteDescriptor } from "./pages/platform-local-account-model";
import { platformOperationsApi } from "./platform/platform-operations-api";
import {
  platformOperationsRouteDescriptor,
  platformSettingsChangedEvent,
  type PlatformGlobalSettingsView,
} from "./platform/platform-operations-model";
import { customerPortalRouteDescriptor } from "./portal/model";
import {
  tenantSettingsChangedEvent,
  tenantSettingsReadPermission,
  tenantSettingsRouteDescriptor,
  type VersionedTenantSettings,
} from "./settings/model";
import { ticketNumberingRouteDescriptor } from "./settings/numbering/model";
import { tenantSettingsApi } from "./settings/tenant-settings-api";
import { slaAdministrationRouteDescriptor } from "./sla/model";
import { OperatorDashboard } from "./ticketing/operator-dashboard";
import { reportingRouteDescriptor } from "./ticketing/reporting-model";
import {
  hasAllTicketPermissionsAtOneScope,
  hasAnyTicketPermission,
} from "./ticketing/ticketing-model";
import { workflowAdministrationRouteDescriptor } from "./workflows/model";

interface TenantBrandStyle extends CSSProperties {
  "--tenant-brand-accent": string;
  "--tenant-brand-primary": string;
}

interface AppShellProps {
  navigateLogoutContinuation?: (continuationUrl: string) => void;
}

export function AppShell({
  navigateLogoutContinuation = assignLogoutContinuation,
}: AppShellProps = {}): React.JSX.Element {
  return (
    <PlatformOperatorTeamCoordinatorProvider>
      <TenantAuthorityProvider>
        <AppShellFrame
          navigateLogoutContinuation={navigateLogoutContinuation}
        />
      </TenantAuthorityProvider>
    </PlatformOperatorTeamCoordinatorProvider>
  );
}

function AppShellFrame(props: Required<AppShellProps>): React.JSX.Element {
  const model = useAppShellFrameModel(props);
  return <AppShellFrameView model={model.data} />;
}

function useAppShellFrameModel({
  navigateLogoutContinuation,
}: Required<AppShellProps>) {
  const { api, clearSession, session, updateSession } = useSession();
  const tenantAuthority = useTenantAuthority();
  const [isLoggingOut, setIsLoggingOut] = useState(false);
  const [sessionError, setSessionError] = useState<string | null>(null);
  const location = useLocation();
  const navigate = useNavigate();
  const mainRef = useRef<HTMLElement>(null);
  const routeTitle = appRouteTitle(location.pathname);
  const {
    canReadTenants,
    canReadPlatformOperatorTeams,
    canReadPlatformIdentityProviders,
    canReadPlatformIdentityBindings,
    canReadPlatformIdentityAccounts,
    canManagePlatformNotifications,
    canAccessContacts,
    canAccessCustomerPortal,
    canReadTenantAudit,
    canReadPlatformAudit,
    canReadPlatformMfaPolicy,
    canReadTenantMfaPolicy,
    canReadTenantSettings,
    canAccessPlatformOperations,
    canReadPlatformSettings,
    canAccessSla,
    canAccessWorkflows,
    canAccessActivity,
    canAccessReports,
    canAccessCustomFields,
    canAccessCustomFieldImports,
  } = shellAccess(session, tenantAuthority);
  const sessionIdRef = useRef(session.id);
  useLayoutEffect(() => {
    sessionIdRef.current = session.id;
  }, [session.id]);
  const tenantBrandPair =
    session.id + ":" + (session.activeTenantId ?? "inactive");
  const [tenantBrandRevision, setTenantBrandRevision] = useState(0);
  const [tenantBrandSnapshot, setTenantBrandSnapshot] = useState<{
    pairKey: string;
    value?: VersionedTenantSettings["value"];
  }>({ pairKey: tenantBrandPair });
  const tenantBrand =
    tenantBrandSnapshot.pairKey === tenantBrandPair
      ? tenantBrandSnapshot.value
      : undefined;
  const [platformSettingsSnapshot, setPlatformSettingsSnapshot] = useState<{
    sessionKey: string;
    value?: PlatformGlobalSettingsView;
  }>({ sessionKey: session.id });
  const [platformSettingsRevision, setPlatformSettingsRevision] = useState(0);
  const platformSettings =
    platformSettingsSnapshot.sessionKey === session.id &&
    !session.activeTenantId
      ? platformSettingsSnapshot.value
      : undefined;
  const shellName =
    tenantBrand?.brandName ?? platformSettings?.platformName ?? "Periapsis";
  const tenantBrandStyle: TenantBrandStyle | undefined = tenantBrand
    ? {
        "--tenant-brand-accent": tenantBrand.accentColor,
        "--tenant-brand-primary": tenantBrand.primaryColor,
      }
    : undefined;

  useEffect(() => {
    setIsLoggingOut(false);
    setSessionError(null);
  }, [session.id]);

  useEffect(() => {
    const tenantId = session.activeTenantId;
    const pairKey = session.id + ":" + (tenantId ?? "inactive");
    setTenantBrandSnapshot({ pairKey });
    if (
      tenantAuthority.status !== "ready" ||
      !tenantId ||
      !canReadTenantSettings
    ) {
      return undefined;
    }

    const controller = new AbortController();
    void tenantSettingsApi
      .get(tenantId, controller.signal)
      .then((settings) => {
        if (!controller.signal.aborted) {
          setTenantBrandSnapshot({ pairKey, value: settings.value });
        }
      })
      .catch(() => {
        if (!controller.signal.aborted) {
          setTenantBrandSnapshot({ pairKey });
        }
      });
    return () => controller.abort();
  }, [
    canReadTenantSettings,
    session.activeTenantId,
    session.id,
    tenantAuthority.status,
    tenantBrandRevision,
  ]);

  useEffect(() => {
    const sessionKey = session.id;
    setPlatformSettingsSnapshot({ sessionKey });
    if (!canReadPlatformSettings) return undefined;

    const controller = new AbortController();
    void platformOperationsApi
      .getSettings({ signal: controller.signal })
      .then((value) => {
        if (!controller.signal.aborted) {
          setPlatformSettingsSnapshot({ sessionKey, value });
        }
      })
      .catch(() => {
        if (!controller.signal.aborted) {
          setPlatformSettingsSnapshot({ sessionKey });
        }
      });
    return () => controller.abort();
  }, [canReadPlatformSettings, platformSettingsRevision, session.id]);

  useEffect(() => {
    const refreshPlatformSettings = (): void => {
      setPlatformSettingsRevision((current) => current + 1);
    };
    window.addEventListener(
      platformSettingsChangedEvent,
      refreshPlatformSettings,
    );
    return () =>
      window.removeEventListener(
        platformSettingsChangedEvent,
        refreshPlatformSettings,
      );
  }, []);

  useEffect(() => {
    const refreshCurrentTenantBrand = (event: Event): void => {
      if (
        event instanceof CustomEvent &&
        event.detail !== null &&
        typeof event.detail === "object" &&
        "tenantId" in event.detail &&
        event.detail.tenantId === session.activeTenantId
      ) {
        setTenantBrandRevision((current) => current + 1);
      }
    };
    window.addEventListener(
      tenantSettingsChangedEvent,
      refreshCurrentTenantBrand,
    );
    return () =>
      window.removeEventListener(
        tenantSettingsChangedEvent,
        refreshCurrentTenantBrand,
      );
  }, [session.activeTenantId]);

  useEffect(() => {
    document.title = `${routeTitle} · ${shellName}`;
    mainRef.current?.focus({ preventScroll: true });
  }, [location.pathname, routeTitle, shellName]);

  const refreshSession = useCallback(async (): Promise<void> => {
    const expectedSessionId = session.id;
    try {
      const refreshed = await api.getSession();
      if (sessionIdRef.current !== expectedSessionId) {
        return;
      }
      if (refreshed) {
        updateSession(expectedSessionId, refreshed);
      } else {
        clearSession(expectedSessionId);
      }
    } catch (caught) {
      if (sessionIdRef.current !== expectedSessionId) {
        return;
      }
      setSessionError(
        describePhaseTwoError(
          caught,
          "The current session could not be revalidated. Server authorization still applies to every request.",
        ),
      );
    }
  }, [api, clearSession, session.id, updateSession]);

  useEffect(() => {
    function revalidateOnFocus(): void {
      void refreshSession();
    }
    window.addEventListener("focus", revalidateOnFocus);
    return () => window.removeEventListener("focus", revalidateOnFocus);
  }, [refreshSession]);

  useEffect(() => {
    const expiresAt = earliestExpiry(
      session.idleExpiresAt,
      session.absoluteExpiresAt,
    );
    if (expiresAt === null) {
      return undefined;
    }
    const maximumDelay = 2_147_483_647;
    const delay = Math.min(
      maximumDelay,
      Math.max(0, expiresAt - Date.now() + 250),
    );
    const timer = window.setTimeout(() => void refreshSession(), delay);
    return () => window.clearTimeout(timer);
  }, [refreshSession, session.absoluteExpiresAt, session.idleExpiresAt]);

  async function logout(): Promise<void> {
    const expectedSessionId = session.id;
    setSessionError(null);
    setIsLoggingOut(true);
    try {
      const result = await api.logout(session.csrfToken);
      if (sessionIdRef.current !== expectedSessionId) {
        return;
      }
      clearSession(expectedSessionId);
      if (result) {
        navigateLogoutContinuation(result.continuationUrl);
      } else {
        void navigate("/");
      }
    } catch (caught) {
      if (sessionIdRef.current !== expectedSessionId) {
        return;
      }
      if (caught instanceof PhaseTwoApiError && caught.status === 401) {
        clearSession(expectedSessionId);
        void navigate("/");
        return;
      }
      setSessionError(
        describePhaseTwoError(
          caught,
          "The server did not confirm logout. The current session remains active; try again.",
        ),
      );
    } finally {
      if (sessionIdRef.current === expectedSessionId) {
        setIsLoggingOut(false);
      }
    }
  }

  return {
    kind: "ready" as const,
    data: {
      canAccessActivity,
      canAccessContacts,
      canAccessCustomFieldImports,
      canAccessCustomFields,
      canAccessCustomerPortal,
      canAccessPlatformOperations,
      canAccessReports,
      canAccessSla,
      canAccessWorkflows,
      canManagePlatformNotifications,
      canReadPlatformAudit,
      canReadPlatformIdentityAccounts,
      canReadPlatformIdentityBindings,
      canReadPlatformIdentityProviders,
      canReadPlatformMfaPolicy,
      canReadPlatformOperatorTeams,
      canReadTenantAudit,
      canReadTenantMfaPolicy,
      canReadTenantSettings,
      canReadTenants,
      isLoggingOut,
      logout,
      mainRef,
      platformSettings,
      routeTitle,
      session,
      sessionError,
      shellName,
      tenantAuthority,
      tenantBrand,
      tenantBrandStyle,
    },
  };
}

function AppShellFrameView({
  model,
}: {
  model: Extract<
    ReturnType<typeof useAppShellFrameModel>,
    { kind: "ready" }
  >["data"];
}): React.JSX.Element {
  const {
    canAccessActivity,
    canAccessContacts,
    canAccessCustomFieldImports,
    canAccessCustomFields,
    canAccessCustomerPortal,
    canAccessPlatformOperations,
    canAccessReports,
    canAccessSla,
    canAccessWorkflows,
    canManagePlatformNotifications,
    canReadPlatformAudit,
    canReadPlatformIdentityAccounts,
    canReadPlatformIdentityBindings,
    canReadPlatformIdentityProviders,
    canReadPlatformMfaPolicy,
    canReadPlatformOperatorTeams,
    canReadTenantAudit,
    canReadTenantMfaPolicy,
    canReadTenantSettings,
    canReadTenants,
    isLoggingOut,
    logout,
    mainRef,
    platformSettings,
    routeTitle,
    session,
    sessionError,
    shellName,
    tenantAuthority,
    tenantBrand,
    tenantBrandStyle,
  } = model;
  return (
    <TenantDateTimeProvider
      locale={tenantBrand?.locale}
      timeZone={tenantBrand?.timezone}
    >
      <div className="app-shell" style={tenantBrandStyle}>
        <a
          className="skip-link"
          href="#main-content"
          onClick={() => mainRef.current?.focus()}
        >
          Skip to main content
        </a>
        <aside className="sidebar" aria-label="Primary navigation">
          <NavLink to="/" className="brand" aria-label={`${shellName} home`}>
            <span
              className={`brand__mark${tenantBrand ? " brand__mark--tenant" : ""}`}
              aria-hidden="true"
            >
              {tenantBrand ? (
                <span className="brand__monogram">{tenantBrand.brandMark}</span>
              ) : (
                <Orbit />
              )}
            </span>
            <span>
              <strong>{shellName}</strong>
              <small>
                {tenantBrand
                  ? `${tenantBrand.timezone} · ${tenantBrand.locale}`
                  : "Incident operations"}
              </small>
            </span>
          </NavLink>

          <TenantSwitcher />

          <ShellNavigation
            access={{
              canAccessActivity: canAccessActivity,
              canAccessContacts: canAccessContacts,
              canAccessCustomerPortal: canAccessCustomerPortal,
              canAccessCustomFieldImports: canAccessCustomFieldImports,
              canAccessCustomFields: canAccessCustomFields,
              canAccessPlatformOperations: canAccessPlatformOperations,
              canAccessReports: canAccessReports,
              canAccessSla: canAccessSla,
              canAccessWorkflows: canAccessWorkflows,
              canManagePlatformNotifications: canManagePlatformNotifications,
              canReadPlatformAudit: canReadPlatformAudit,
              canReadPlatformIdentityAccounts: canReadPlatformIdentityAccounts,
              canReadPlatformIdentityBindings: canReadPlatformIdentityBindings,
              canReadPlatformIdentityProviders:
                canReadPlatformIdentityProviders,
              canReadPlatformMfaPolicy: canReadPlatformMfaPolicy,
              canReadPlatformOperatorTeams: canReadPlatformOperatorTeams,
              canReadTenantAudit: canReadTenantAudit,
              canReadTenantMfaPolicy: canReadTenantMfaPolicy,
              canReadTenants: canReadTenants,
              canReadTenantSettings: canReadTenantSettings,
              session: session,
              tenantAuthority: tenantAuthority,
            }}
          />

          <div className="sidebar__footer">
            <Separator />
            {platformSettings?.supportUrl ? (
              <a
                href={platformSettings.supportUrl}
                className="support-link"
                target="_blank"
                rel="noopener noreferrer"
              >
                <LifeBuoy aria-hidden="true" /> Support
                <ArrowUpRight aria-hidden="true" />
              </a>
            ) : null}
            <a href="/docs" className="support-link">
              <LifeBuoy aria-hidden="true" /> API contract
              <ArrowUpRight aria-hidden="true" />
            </a>
          </div>
        </aside>

        <main
          ref={mainRef}
          id="main-content"
          className="main-panel"
          aria-label="Main content"
          tabIndex={-1}
        >
          <p className="sr-only" aria-atomic="true" aria-live="polite">
            {routeTitle}
          </p>
          <header className="topbar">
            <div>
              <p className="eyebrow">Authenticated control plane</p>
              <p className="topbar__context">
                {session.activeTenantId
                  ? tenantBrand
                    ? `${tenantBrand.brandName} · tenant context active`
                    : "Tenant context active"
                  : "Platform context · no active tenant"}
              </p>
            </div>
            <div className="topbar__identity">
              <div className="identity-summary" aria-label="Current session">
                <CircleUserRound aria-hidden="true" />
                <span>
                  <small>Signed in</small>
                  <strong>{session.user.displayName}</strong>
                </span>
              </div>
              <Button
                type="button"
                variant="ghost"
                size="sm"
                onClick={() => void logout()}
                disabled={isLoggingOut}
              >
                <LogOut aria-hidden="true" />
                {isLoggingOut ? "Signing out…" : "Sign out"}
              </Button>
            </div>
          </header>
          {sessionError ? (
            <div className="session-error">
              <FocusedError
                message={sessionError}
                title="Session action failed"
              />
            </div>
          ) : null}
          <Outlet />
        </main>
      </div>
    </TenantDateTimeProvider>
  );
}

function assignLogoutContinuation(continuationUrl: string): void {
  globalThis.location.assign(continuationUrl);
}

export function ControlPlaneOverview(): React.JSX.Element {
  const { session } = useSession();
  const { formatInstant } = useTenantDateTime();
  const statusQuery = useQuery({
    queryKey: ["system-status"],
    queryFn: loadSystemStatus,
    retry: 1,
    refetchInterval: 30_000,
  });

  return (
    <div className="content">
      <section className="intro" aria-labelledby="page-title">
        <div
          className="orbital-signature orbital-signature--authenticated"
          aria-hidden="true"
        >
          <span className="orbital-signature__track" />
          <span className="orbital-signature__body" />
          <ShieldCheck />
        </div>
        <div className="intro__copy">
          <p className="section-label">Access orbit / Phase 2A</p>
          <h1 id="page-title">The operator perimeter is active.</h1>
          <p>
            The server authenticated {session.user.displayName}, proved MFA, and
            returned the permissions and tenant context shown here. Every
            operation remains subject to backend policy and PostgreSQL RLS.
          </p>
          <div className="intro__actions">
            <Button
              variant="outline"
              onClick={() => void statusQuery.refetch()}
              disabled={statusQuery.isFetching}
            >
              <RefreshCw
                className={statusQuery.isFetching ? "is-spinning" : undefined}
                aria-hidden="true"
              />
              {statusQuery.isFetching
                ? "Checking platform…"
                : "Recheck platform"}
            </Button>
          </div>
        </div>
      </section>

      <section className="session-facts" aria-label="Current access summary">
        <AccessFact
          icon={<CircleUserRound aria-hidden="true" />}
          label="Identity"
          value={session.user.email ?? session.user.displayName}
        />
        <AccessFact
          icon={<Clock3 aria-hidden="true" />}
          label="Session expiry"
          value={formatInstant(session.idleExpiresAt, {
            invalidLabel: "Unavailable",
          })}
        />
        <AccessFact
          icon={<KeyRound aria-hidden="true" />}
          label="Server permissions"
          value={`${session.permissions.length} explicit`}
        />
      </section>

      <OperatorDashboard />

      <section aria-live="polite" aria-busy={statusQuery.isPending}>
        {statusQuery.data ? <StatusPanel status={statusQuery.data} /> : null}
        {statusQuery.isPending ? <StatusSkeleton /> : null}
        {statusQuery.isError ? (
          <div className="status-error" role="alert">
            <strong>The API readiness check did not respond.</strong>
            <p>
              Your session is not treated as authorization evidence for this
              failed check. Confirm the API service and retry.
            </p>
          </div>
        ) : null}
      </section>

      <section className="boundary-note" aria-labelledby="boundary-note-title">
        <div>
          <p className="section-label">Current delivery boundary</p>
          <h2 id="boundary-note-title">
            Incident work now carries its own perimeter.
          </h2>
        </div>
        <p>
          Alert and Case queues, versioned actions, customer-safe comments,
          escalation, DFIR evidence, SLA controls, notifications, workflows, and
          audit inspection now pass through governed backend use cases. Every
          dashboard shortcut is only a bounded view of that live policy.
        </p>
      </section>
    </div>
  );
}

interface AccessFactProps {
  icon: React.ReactNode;
  label: string;
  value: string;
}

function AccessFact({
  icon,
  label,
  value,
}: AccessFactProps): React.JSX.Element {
  return (
    <Card className="access-fact">
      <CardHeader>
        <span className="access-fact__icon">{icon}</span>
        <div>
          <CardDescription>{label}</CardDescription>
          <CardTitle>{value}</CardTitle>
        </div>
      </CardHeader>
      <CardContent>
        <Badge variant="outline">Server returned</Badge>
      </CardContent>
    </Card>
  );
}

function StatusSkeleton(): React.JSX.Element {
  return (
    <div className="status-skeleton" aria-label="Checking platform readiness">
      <span />
      <span />
      <span />
    </div>
  );
}

function earliestExpiry(idle: string, absolute: string): number | null {
  const values = [Date.parse(idle), Date.parse(absolute)].filter(
    (value) => !Number.isNaN(value),
  );
  return values.length > 0 ? Math.min(...values) : null;
}

interface ShellNavigationAccess {
  canAccessActivity: boolean;
  canAccessContacts: boolean;
  canAccessCustomerPortal: boolean;
  canAccessCustomFieldImports: boolean;
  canAccessCustomFields: boolean;
  canAccessPlatformOperations: boolean;
  canAccessReports: boolean;
  canAccessSla: boolean;
  canAccessWorkflows: boolean;
  canManagePlatformNotifications: boolean;
  canReadPlatformAudit: boolean;
  canReadPlatformIdentityAccounts: boolean;
  canReadPlatformIdentityBindings: boolean;
  canReadPlatformIdentityProviders: boolean;
  canReadPlatformMfaPolicy: boolean;
  canReadPlatformOperatorTeams: boolean;
  canReadTenantAudit: boolean;
  canReadTenantMfaPolicy: boolean;
  canReadTenants: boolean;
  canReadTenantSettings: boolean;
  session: ReturnType<typeof useSession>["session"];
  tenantAuthority: ReturnType<typeof useTenantAuthority>;
}

function shellNavigationItems({
  canAccessActivity,
  canAccessContacts,
  canAccessCustomerPortal,
  canAccessCustomFieldImports,
  canAccessCustomFields,
  canAccessPlatformOperations,
  canAccessReports,
  canAccessSla,
  canAccessWorkflows,
  canManagePlatformNotifications,
  canReadPlatformAudit,
  canReadPlatformIdentityAccounts,
  canReadPlatformIdentityBindings,
  canReadPlatformIdentityProviders,
  canReadPlatformMfaPolicy,
  canReadPlatformOperatorTeams,
  canReadTenantAudit,
  canReadTenantMfaPolicy,
  canReadTenants,
  canReadTenantSettings,
  session,
  tenantAuthority,
}: ShellNavigationAccess) {
  return [
    {
      to: "/",
      end: true,
      label: "Overview",
      Icon: Activity,
      visible: true,
    },
    {
      to: "/profile",
      end: false,
      label: "Profile",
      Icon: CircleUserRound,
      visible: true,
    },
    {
      to: "/sessions",
      end: false,
      label: "Sessions",
      Icon: Laptop,
      visible: true,
    },
    {
      to: mfaSecurityRouteDescriptor.path,
      end: false,
      label: mfaSecurityRouteDescriptor.label,
      Icon: KeyRound,
      visible: Boolean(session.activeTenantId),
    },
    {
      to: notificationInboxRouteDescriptor.path,
      end: false,
      label: notificationInboxRouteDescriptor.label,
      Icon: Inbox,
      visible: Boolean(session.activeTenantId),
    },
    {
      to: "/alerts",
      end: false,
      label: "Alerts",
      Icon: BellRing,
      visible: hasAnyTicketPermission(
        tenantAuthority.hasPermission,
        "alert.read",
      ),
    },
    {
      to: "/activity",
      end: false,
      label: "Activity",
      Icon: Activity,
      visible: canAccessActivity,
    },
    {
      to: "/cases",
      end: false,
      label: "Cases",
      Icon: BriefcaseBusiness,
      visible: hasAnyTicketPermission(
        tenantAuthority.hasPermission,
        "case.read",
      ),
    },
    {
      to: reportingRouteDescriptor.path,
      end: false,
      label: reportingRouteDescriptor.label,
      Icon: FileSpreadsheet,
      visible: canAccessReports,
    },
    {
      to: "/search",
      end: false,
      label: "Global search",
      Icon: Search,
      visible:
        hasAnyTicketPermission(tenantAuthority.hasPermission, "alert.read") ||
        hasAnyTicketPermission(tenantAuthority.hasPermission, "case.read"),
    },
    {
      to: customerPortalRouteDescriptor.path,
      end: false,
      label: "Customer portal",
      Icon: ShieldCheck,
      visible: canAccessCustomerPortal,
    },
    {
      to: "/tenant/users",
      end: false,
      label: "Users",
      Icon: Users,
      visible: tenantAuthority.hasPermission("user.read"),
    },
    {
      to: "/tenant/roles",
      end: false,
      label: "Roles",
      Icon: Shield,
      visible: tenantAuthority.hasPermission("role.read"),
    },
    {
      to: "/tenant/groups",
      end: false,
      label: "Groups",
      Icon: Network,
      visible: tenantAuthority.hasPermission("group.read"),
    },
    {
      to: contactAdministrationRouteDescriptor.path,
      end: false,
      label: "Customer contacts",
      Icon: ContactRound,
      visible: canAccessContacts,
    },
    {
      to: tenantAuditRouteDescriptor.path,
      end: false,
      label: "Tenant audit",
      Icon: FileClock,
      visible: canReadTenantAudit,
    },
    {
      to: tenantSettingsRouteDescriptor.path,
      end: true,
      label: tenantSettingsRouteDescriptor.label,
      Icon: Palette,
      visible: canReadTenantSettings,
    },
    {
      to: ticketNumberingRouteDescriptor.path,
      end: false,
      label: ticketNumberingRouteDescriptor.label,
      Icon: Hash,
      visible: canReadTenantSettings,
    },
    {
      to: slaAdministrationRouteDescriptor.path,
      end: false,
      label: "SLA control room",
      Icon: Gauge,
      visible: canAccessSla,
    },
    {
      to: workflowAdministrationRouteDescriptor.path,
      end: false,
      label: "Workflows",
      Icon: GitBranch,
      visible: canAccessWorkflows,
    },
    {
      to: customFieldAdministrationRouteDescriptor.path,
      end: false,
      label: customFieldAdministrationRouteDescriptor.label,
      Icon: Braces,
      visible: canAccessCustomFields,
    },
    {
      to: customFieldImportRouteDescriptor.path,
      end: false,
      label: customFieldImportRouteDescriptor.label,
      Icon: FileJson2,
      visible: canAccessCustomFieldImports,
    },
    {
      to: "/tenant/operator-teams",
      end: false,
      label: "Operator teams",
      Icon: UsersRound,
      visible: tenantAuthority.hasPermission("operator_team.read", "tenant"),
    },
    {
      to: "/tenant/identity-providers",
      end: false,
      label: "Identity providers",
      Icon: ServerCog,
      visible: tenantAuthority.hasPermission(
        "identity_provider.read",
        "tenant",
      ),
    },
    {
      to: tenantFederationRouteDescriptor.path,
      end: false,
      label: tenantFederationRouteDescriptor.label,
      Icon: RadioTower,
      visible: tenantAuthority.hasPermission(
        "identity_provider.read",
        "tenant",
      ),
    },
    {
      to: tenantMfaPolicyRouteDescriptor.path,
      end: false,
      label: tenantMfaPolicyRouteDescriptor.label,
      Icon: ShieldCheck,
      visible: canReadTenantMfaPolicy,
    },
    {
      to: "/tenant/service-accounts",
      end: false,
      label: "Service accounts",
      Icon: Bot,
      visible: tenantAuthority.hasPermission("service_account.read", "tenant"),
    },
    {
      to: tenantNotificationRouteDescriptor.path,
      end: false,
      label: "Notifications",
      Icon: Send,
      visible: tenantAuthority.hasPermission(
        tenantNotificationPermission,
        "tenant",
      ),
    },
    {
      to: "/platform/tenants",
      end: false,
      label: "Platform tenants",
      Icon: Building2,
      visible: canReadTenants,
    },
    {
      to: platformOperationsRouteDescriptor.path,
      end: false,
      label: platformOperationsRouteDescriptor.label,
      Icon: Gauge,
      visible: canAccessPlatformOperations,
    },
    {
      to: "/platform/operator-teams",
      end: false,
      label: "Platform teams",
      Icon: RadioTower,
      visible: canReadPlatformOperatorTeams,
    },
    {
      to: platformAuthProviderRouteDescriptor.path,
      end: false,
      label: platformAuthProviderRouteDescriptor.label,
      Icon: Fingerprint,
      visible:
        canReadPlatformIdentityProviders ||
        canReadPlatformIdentityBindings ||
        canReadPlatformIdentityAccounts,
    },
    {
      to: platformLocalAccountRouteDescriptor.path,
      end: false,
      label: platformLocalAccountRouteDescriptor.label,
      Icon: KeyRound,
      visible: canReadPlatformIdentityAccounts,
    },
    {
      to: platformSmtpRouteDescriptor.path,
      end: false,
      label: "Platform SMTP",
      Icon: MailCheck,
      visible: canManagePlatformNotifications,
    },
    {
      to: platformMfaPolicyRouteDescriptor.path,
      end: false,
      label: platformMfaPolicyRouteDescriptor.label,
      Icon: ShieldCheck,
      visible: canReadPlatformMfaPolicy,
    },
    {
      to: platformAuditRouteDescriptor.path,
      end: false,
      label: "Platform audit",
      Icon: FileClock,
      visible: canReadPlatformAudit,
    },
  ];
}

function ShellNavigation({
  access,
}: {
  access: ShellNavigationAccess;
}): React.JSX.Element {
  return (
    <nav className="nav-list" aria-label="Workspace">
      {shellNavigationItems(access).map((item) =>
        item.visible ? (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.end}
            className={navigationClassName}
          >
            <item.Icon aria-hidden="true" />
            <span>{item.label}</span>
          </NavLink>
        ) : null,
      )}
    </nav>
  );
}

function navigationClassName({ isActive }: { isActive: boolean }): string {
  return "nav-item" + (isActive ? " nav-item--active" : "");
}

function shellAccess(
  session: ReturnType<typeof useSession>["session"],
  tenantAuthority: ReturnType<typeof useTenantAuthority>,
) {
  const canReadTenants = hasPermission(session, platformTenantReadPermission);
  const canReadPlatformOperatorTeams = hasPermission(
    session,
    platformOperatorTeamReadPermission,
  );
  const canReadPlatformIdentityProviders = hasPermission(
    session,
    platformIdentityProviderReadPermission,
  );
  const canReadPlatformIdentityBindings = hasPermission(
    session,
    platformIdentityBindingReadPermission,
  );
  const canReadPlatformIdentityAccounts = hasPermission(
    session,
    platformIdentityAccountReadPermission,
  );
  const canManagePlatformNotifications = hasPermission(
    session,
    platformNotificationPermission,
  );
  const canAccessContacts =
    contactAdministrationRouteDescriptor.permissions.some((permission) =>
      tenantAuthority.hasPermission(permission, "tenant"),
    );
  const canAccessCustomerPortal =
    customerPortalRouteDescriptor.permissions.some((permission) =>
      tenantAuthority.hasPermission(permission, "own"),
    );
  const canReadTenantAudit = tenantAuthority.hasPermission(
    tenantAuditPermission,
    "tenant",
  );
  const canReadPlatformAudit = hasPermission(session, platformAuditPermission);
  const canReadPlatformMfaPolicy = hasPermission(
    session,
    platformMfaPolicyReadPermission,
  );
  const canReadTenantMfaPolicy = tenantAuthority.hasPermission(
    tenantMfaPolicyReadPermission,
    "tenant",
  );
  const canReadTenantSettings = tenantAuthority.hasPermission(
    tenantSettingsReadPermission,
    "tenant",
  );
  const canAccessPlatformOperations =
    !session.activeTenantId &&
    platformOperationsRouteDescriptor.permissions.some((permission) =>
      hasPermission(session, permission),
    );
  const canReadPlatformSettings =
    !session.activeTenantId &&
    hasPermission(session, platformSettingsReadPermission);
  const canAccessSla =
    tenantAuthority.hasPermission("sla.read", "tenant") ||
    tenantAuthority.hasPermission("sla.manage", "tenant") ||
    tenantAuthority.hasPermission("sla.simulate", "tenant");
  const canAccessWorkflows =
    workflowAdministrationRouteDescriptor.permissions.some((permission) =>
      tenantAuthority.hasPermission(permission, "tenant"),
    );
  const canAccessActivity =
    hasAllTicketPermissionsAtOneScope(tenantAuthority.hasPermission, [
      "alert.read",
      "alert.activity.read",
    ]) ||
    hasAllTicketPermissionsAtOneScope(tenantAuthority.hasPermission, [
      "case.read",
      "case.activity.read",
    ]);
  const canAccessReports =
    hasAnyTicketPermission(tenantAuthority.hasPermission, "alert.read") ||
    hasAnyTicketPermission(tenantAuthority.hasPermission, "case.read");
  const canAccessCustomFields =
    customFieldAdministrationRouteDescriptor.permissions.some((permission) =>
      tenantAuthority.hasPermission(permission, "tenant"),
    );
  const canAccessCustomFieldImports =
    canAccessCustomFields &&
    (hasAnyTicketPermission(tenantAuthority.hasPermission, "alert.update") ||
      hasAnyTicketPermission(tenantAuthority.hasPermission, "case.update"));
  return {
    canReadTenants,
    canReadPlatformOperatorTeams,
    canReadPlatformIdentityProviders,
    canReadPlatformIdentityBindings,
    canReadPlatformIdentityAccounts,
    canManagePlatformNotifications,
    canAccessContacts,
    canAccessCustomerPortal,
    canReadTenantAudit,
    canReadPlatformAudit,
    canReadPlatformMfaPolicy,
    canReadTenantMfaPolicy,
    canReadTenantSettings,
    canAccessPlatformOperations,
    canReadPlatformSettings,
    canAccessSla,
    canAccessWorkflows,
    canAccessActivity,
    canAccessReports,
    canAccessCustomFields,
    canAccessCustomFieldImports,
  };
}
