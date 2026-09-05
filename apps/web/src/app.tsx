import { useQuery } from "@tanstack/react-query";
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
import {
  Activity,
  ArrowUpRight,
  BellRing,
  Bot,
  BriefcaseBusiness,
  Braces,
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
  RefreshCw,
  RadioTower,
  Search,
  ServerCog,
  Shield,
  ShieldCheck,
  Send,
  Users,
  UsersRound,
} from "lucide-react";
import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type CSSProperties,
} from "react";
import { NavLink, Outlet, useLocation, useNavigate } from "react-router";

import { useSession } from "./auth/session-context";
import { mfaSecurityRouteDescriptor } from "./auth/mfa/model";
import { PlatformOperatorTeamCoordinatorProvider } from "./auth/platform-operator-team-coordinator";
import {
  TenantAuthorityProvider,
  useTenantAuthority,
} from "./auth/tenant-authority-context";
import { FocusedError } from "./components/focused-error";
import { StatusPanel } from "./components/status-panel";
import { TenantSwitcher } from "./components/tenant-switcher";
import { contactAdministrationRouteDescriptor } from "./contacts/model";
import { customFieldAdministrationRouteDescriptor } from "./customfields/model";
import { customFieldImportRouteDescriptor } from "./customfields/custom-field-import-model";
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
import {
  TenantDateTimeProvider,
  useTenantDateTime,
} from "./lib/tenant-date-time-context";
import {
  platformMfaPolicyReadPermission,
  platformMfaPolicyRouteDescriptor,
  tenantMfaPolicyReadPermission,
  tenantMfaPolicyRouteDescriptor,
} from "./mfapolicy/model";
import {
  hasAllTicketPermissionsAtOneScope,
  hasAnyTicketPermission,
} from "./ticketing/ticketing-model";
import { OperatorDashboard } from "./ticketing/operator-dashboard";
import { reportingRouteDescriptor } from "./ticketing/reporting-model";
import {
  notificationInboxRouteDescriptor,
  platformNotificationPermission,
  platformSmtpRouteDescriptor,
  tenantNotificationPermission,
  tenantNotificationRouteDescriptor,
} from "./notifications";
import { customerPortalRouteDescriptor } from "./portal/model";
import { slaAdministrationRouteDescriptor } from "./sla/model";
import { workflowAdministrationRouteDescriptor } from "./workflows/model";
import { platformAuthProviderRouteDescriptor } from "./pages/platform-auth-provider-model";
import { platformLocalAccountRouteDescriptor } from "./pages/platform-local-account-model";
import {
  platformAuditPermission,
  platformAuditRouteDescriptor,
  tenantAuditPermission,
  tenantAuditRouteDescriptor,
} from "./audit/model";
import {
  tenantSettingsChangedEvent,
  tenantSettingsReadPermission,
  tenantSettingsRouteDescriptor,
  type VersionedTenantSettings,
} from "./settings/model";
import { tenantSettingsApi } from "./settings/tenant-settings-api";
import { ticketNumberingRouteDescriptor } from "./settings/numbering/model";
import { platformOperationsApi } from "./platform/platform-operations-api";
import {
  platformOperationsRouteDescriptor,
  platformSettingsChangedEvent,
  type PlatformGlobalSettingsView,
} from "./platform/platform-operations-model";

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

function AppShellFrame({
  navigateLogoutContinuation,
}: Required<AppShellProps>): React.JSX.Element {
  const { api, clearSession, session, updateSession } = useSession();
  const tenantAuthority = useTenantAuthority();
  const [isLoggingOut, setIsLoggingOut] = useState(false);
  const [sessionError, setSessionError] = useState<string | null>(null);
  const location = useLocation();
  const navigate = useNavigate();
  const mainRef = useRef<HTMLElement>(null);
  const routeTitle = appRouteTitle(location.pathname);
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
  const sessionIdRef = useRef(session.id);
  sessionIdRef.current = session.id;
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

          <nav className="nav-list" aria-label="Workspace">
            <NavLink
              to="/"
              end
              className={({ isActive }) =>
                `nav-item${isActive ? " nav-item--active" : ""}`
              }
            >
              <Activity aria-hidden="true" />
              <span>Overview</span>
            </NavLink>
            <NavLink
              to="/profile"
              className={({ isActive }) =>
                `nav-item${isActive ? " nav-item--active" : ""}`
              }
            >
              <CircleUserRound aria-hidden="true" />
              <span>Profile</span>
            </NavLink>
            <NavLink
              to="/sessions"
              className={({ isActive }) =>
                `nav-item${isActive ? " nav-item--active" : ""}`
              }
            >
              <Laptop aria-hidden="true" />
              <span>Sessions</span>
            </NavLink>
            {session.activeTenantId ? (
              <NavLink
                to={mfaSecurityRouteDescriptor.path}
                className={({ isActive }) =>
                  `nav-item${isActive ? " nav-item--active" : ""}`
                }
              >
                <KeyRound aria-hidden="true" />
                <span>{mfaSecurityRouteDescriptor.label}</span>
              </NavLink>
            ) : null}
            {session.activeTenantId ? (
              <NavLink
                to={notificationInboxRouteDescriptor.path}
                className={({ isActive }) =>
                  `nav-item${isActive ? " nav-item--active" : ""}`
                }
              >
                <Inbox aria-hidden="true" />
                <span>{notificationInboxRouteDescriptor.label}</span>
              </NavLink>
            ) : null}
            {hasAnyTicketPermission(
              tenantAuthority.hasPermission,
              "alert.read",
            ) ? (
              <NavLink
                to="/alerts"
                className={({ isActive }) =>
                  `nav-item${isActive ? " nav-item--active" : ""}`
                }
              >
                <BellRing aria-hidden="true" />
                <span>Alerts</span>
              </NavLink>
            ) : null}
            {canAccessActivity ? (
              <NavLink
                to="/activity"
                className={({ isActive }) =>
                  `nav-item${isActive ? " nav-item--active" : ""}`
                }
              >
                <Activity aria-hidden="true" />
                <span>Activity</span>
              </NavLink>
            ) : null}
            {hasAnyTicketPermission(
              tenantAuthority.hasPermission,
              "case.read",
            ) ? (
              <NavLink
                to="/cases"
                className={({ isActive }) =>
                  `nav-item${isActive ? " nav-item--active" : ""}`
                }
              >
                <BriefcaseBusiness aria-hidden="true" />
                <span>Cases</span>
              </NavLink>
            ) : null}
            {canAccessReports ? (
              <NavLink
                to={reportingRouteDescriptor.path}
                className={({ isActive }) =>
                  `nav-item${isActive ? " nav-item--active" : ""}`
                }
              >
                <FileSpreadsheet aria-hidden="true" />
                <span>{reportingRouteDescriptor.label}</span>
              </NavLink>
            ) : null}
            {hasAnyTicketPermission(
              tenantAuthority.hasPermission,
              "alert.read",
            ) ||
            hasAnyTicketPermission(
              tenantAuthority.hasPermission,
              "case.read",
            ) ? (
              <NavLink
                to="/search"
                className={({ isActive }) =>
                  `nav-item${isActive ? " nav-item--active" : ""}`
                }
              >
                <Search aria-hidden="true" />
                <span>Global search</span>
              </NavLink>
            ) : null}
            {canAccessCustomerPortal ? (
              <NavLink
                to={customerPortalRouteDescriptor.path}
                className={({ isActive }) =>
                  `nav-item${isActive ? " nav-item--active" : ""}`
                }
              >
                <ShieldCheck aria-hidden="true" />
                <span>Customer portal</span>
              </NavLink>
            ) : null}
            {tenantAuthority.hasPermission("user.read") ? (
              <NavLink
                to="/tenant/users"
                className={({ isActive }) =>
                  `nav-item${isActive ? " nav-item--active" : ""}`
                }
              >
                <Users aria-hidden="true" />
                <span>Users</span>
              </NavLink>
            ) : null}
            {tenantAuthority.hasPermission("role.read") ? (
              <NavLink
                to="/tenant/roles"
                className={({ isActive }) =>
                  `nav-item${isActive ? " nav-item--active" : ""}`
                }
              >
                <Shield aria-hidden="true" />
                <span>Roles</span>
              </NavLink>
            ) : null}
            {tenantAuthority.hasPermission("group.read") ? (
              <NavLink
                to="/tenant/groups"
                className={({ isActive }) =>
                  `nav-item${isActive ? " nav-item--active" : ""}`
                }
              >
                <Network aria-hidden="true" />
                <span>Groups</span>
              </NavLink>
            ) : null}
            {canAccessContacts ? (
              <NavLink
                to={contactAdministrationRouteDescriptor.path}
                className={({ isActive }) =>
                  `nav-item${isActive ? " nav-item--active" : ""}`
                }
              >
                <ContactRound aria-hidden="true" />
                <span>Customer contacts</span>
              </NavLink>
            ) : null}
            {canReadTenantAudit ? (
              <NavLink
                to={tenantAuditRouteDescriptor.path}
                className={({ isActive }) =>
                  `nav-item${isActive ? " nav-item--active" : ""}`
                }
              >
                <FileClock aria-hidden="true" />
                <span>Tenant audit</span>
              </NavLink>
            ) : null}
            {canReadTenantSettings ? (
              <NavLink
                to={tenantSettingsRouteDescriptor.path}
                end
                className={({ isActive }) =>
                  `nav-item${isActive ? " nav-item--active" : ""}`
                }
              >
                <Palette aria-hidden="true" />
                <span>{tenantSettingsRouteDescriptor.label}</span>
              </NavLink>
            ) : null}
            {canReadTenantSettings ? (
              <NavLink
                to={ticketNumberingRouteDescriptor.path}
                className={({ isActive }) =>
                  `nav-item${isActive ? " nav-item--active" : ""}`
                }
              >
                <Hash aria-hidden="true" />
                <span>{ticketNumberingRouteDescriptor.label}</span>
              </NavLink>
            ) : null}
            {canAccessSla ? (
              <NavLink
                to={slaAdministrationRouteDescriptor.path}
                className={({ isActive }) =>
                  `nav-item${isActive ? " nav-item--active" : ""}`
                }
              >
                <Gauge aria-hidden="true" />
                <span>SLA control room</span>
              </NavLink>
            ) : null}
            {canAccessWorkflows ? (
              <NavLink
                to={workflowAdministrationRouteDescriptor.path}
                className={({ isActive }) =>
                  `nav-item${isActive ? " nav-item--active" : ""}`
                }
              >
                <GitBranch aria-hidden="true" />
                <span>Workflows</span>
              </NavLink>
            ) : null}
            {canAccessCustomFields ? (
              <NavLink
                to={customFieldAdministrationRouteDescriptor.path}
                className={({ isActive }) =>
                  `nav-item${isActive ? " nav-item--active" : ""}`
                }
              >
                <Braces aria-hidden="true" />
                <span>{customFieldAdministrationRouteDescriptor.label}</span>
              </NavLink>
            ) : null}
            {canAccessCustomFieldImports ? (
              <NavLink
                to={customFieldImportRouteDescriptor.path}
                className={({ isActive }) =>
                  `nav-item${isActive ? " nav-item--active" : ""}`
                }
              >
                <FileJson2 aria-hidden="true" />
                <span>{customFieldImportRouteDescriptor.label}</span>
              </NavLink>
            ) : null}
            {tenantAuthority.hasPermission("operator_team.read", "tenant") ? (
              <NavLink
                to="/tenant/operator-teams"
                className={({ isActive }) =>
                  `nav-item${isActive ? " nav-item--active" : ""}`
                }
              >
                <UsersRound aria-hidden="true" />
                <span>Operator teams</span>
              </NavLink>
            ) : null}
            {tenantAuthority.hasPermission(
              "identity_provider.read",
              "tenant",
            ) ? (
              <>
                <NavLink
                  to="/tenant/identity-providers"
                  className={({ isActive }) =>
                    `nav-item${isActive ? " nav-item--active" : ""}`
                  }
                >
                  <ServerCog aria-hidden="true" />
                  <span>Identity providers</span>
                </NavLink>
                <NavLink
                  to={tenantFederationRouteDescriptor.path}
                  className={({ isActive }) =>
                    `nav-item${isActive ? " nav-item--active" : ""}`
                  }
                >
                  <RadioTower aria-hidden="true" />
                  <span>{tenantFederationRouteDescriptor.label}</span>
                </NavLink>
              </>
            ) : null}
            {canReadTenantMfaPolicy ? (
              <NavLink
                to={tenantMfaPolicyRouteDescriptor.path}
                className={({ isActive }) =>
                  `nav-item${isActive ? " nav-item--active" : ""}`
                }
              >
                <ShieldCheck aria-hidden="true" />
                <span>{tenantMfaPolicyRouteDescriptor.label}</span>
              </NavLink>
            ) : null}
            {tenantAuthority.hasPermission("service_account.read", "tenant") ? (
              <NavLink
                to="/tenant/service-accounts"
                className={({ isActive }) =>
                  `nav-item${isActive ? " nav-item--active" : ""}`
                }
              >
                <Bot aria-hidden="true" />
                <span>Service accounts</span>
              </NavLink>
            ) : null}
            {tenantAuthority.hasPermission(
              tenantNotificationPermission,
              "tenant",
            ) ? (
              <NavLink
                to={tenantNotificationRouteDescriptor.path}
                className={({ isActive }) =>
                  `nav-item${isActive ? " nav-item--active" : ""}`
                }
              >
                <Send aria-hidden="true" />
                <span>Notifications</span>
              </NavLink>
            ) : null}
            {canReadTenants ? (
              <NavLink
                to="/platform/tenants"
                className={({ isActive }) =>
                  `nav-item${isActive ? " nav-item--active" : ""}`
                }
              >
                <Building2 aria-hidden="true" />
                <span>Platform tenants</span>
              </NavLink>
            ) : null}
            {canAccessPlatformOperations ? (
              <NavLink
                to={platformOperationsRouteDescriptor.path}
                className={({ isActive }) =>
                  `nav-item${isActive ? " nav-item--active" : ""}`
                }
              >
                <Gauge aria-hidden="true" />
                <span>{platformOperationsRouteDescriptor.label}</span>
              </NavLink>
            ) : null}
            {canReadPlatformOperatorTeams ? (
              <NavLink
                to="/platform/operator-teams"
                className={({ isActive }) =>
                  `nav-item${isActive ? " nav-item--active" : ""}`
                }
              >
                <RadioTower aria-hidden="true" />
                <span>Platform teams</span>
              </NavLink>
            ) : null}
            {canReadPlatformIdentityProviders ||
            canReadPlatformIdentityBindings ||
            canReadPlatformIdentityAccounts ? (
              <NavLink
                to={platformAuthProviderRouteDescriptor.path}
                className={({ isActive }) =>
                  `nav-item${isActive ? " nav-item--active" : ""}`
                }
              >
                <Fingerprint aria-hidden="true" />
                <span>{platformAuthProviderRouteDescriptor.label}</span>
              </NavLink>
            ) : null}
            {canReadPlatformIdentityAccounts ? (
              <NavLink
                to={platformLocalAccountRouteDescriptor.path}
                className={({ isActive }) =>
                  `nav-item${isActive ? " nav-item--active" : ""}`
                }
              >
                <KeyRound aria-hidden="true" />
                <span>{platformLocalAccountRouteDescriptor.label}</span>
              </NavLink>
            ) : null}
            {canManagePlatformNotifications ? (
              <NavLink
                to={platformSmtpRouteDescriptor.path}
                className={({ isActive }) =>
                  `nav-item${isActive ? " nav-item--active" : ""}`
                }
              >
                <MailCheck aria-hidden="true" />
                <span>Platform SMTP</span>
              </NavLink>
            ) : null}
            {canReadPlatformMfaPolicy ? (
              <NavLink
                to={platformMfaPolicyRouteDescriptor.path}
                className={({ isActive }) =>
                  `nav-item${isActive ? " nav-item--active" : ""}`
                }
              >
                <ShieldCheck aria-hidden="true" />
                <span>{platformMfaPolicyRouteDescriptor.label}</span>
              </NavLink>
            ) : null}
            {canReadPlatformAudit ? (
              <NavLink
                to={platformAuditRouteDescriptor.path}
                className={({ isActive }) =>
                  `nav-item${isActive ? " nav-item--active" : ""}`
                }
              >
                <FileClock aria-hidden="true" />
                <span>Platform audit</span>
              </NavLink>
            ) : null}
          </nav>

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

export function appRouteTitle(pathname: string): string {
  const path = pathname.replace(/\/+$/, "") || "/";
  const exactTitles: Readonly<Record<string, string>> = {
    "/": "Overview",
    "/activity": "Activity",
    "/account/security": "MFA security",
    "/alerts": "Alerts",
    "/alerts/new": "Create Alert",
    "/cases": "Cases",
    "/cases/new": "Create Case",
    "/platform/audit": "Platform audit",
    "/platform/identity-providers": "Platform identity providers",
    "/platform/local-accounts": "Platform local accounts",
    "/platform/mfa-policies": "Platform MFA policies",
    "/platform/notifications/smtp": "Platform SMTP",
    "/platform/operator-teams": "Platform operator teams",
    "/platform/operations": "Platform operations",
    "/platform/tenants": "Platform tenants",
    "/portal": "Customer portal",
    "/profile": "User profile",
    [notificationInboxRouteDescriptor.path]:
      notificationInboxRouteDescriptor.label,
    [reportingRouteDescriptor.path]: reportingRouteDescriptor.label,
    "/search": "Global search",
    "/sessions": "Sessions",
    "/tenant/audit": "Tenant audit",
    "/tenant/contacts": "Contacts",
    "/tenant/custom-fields": "Custom fields",
    [customFieldImportRouteDescriptor.path]:
      customFieldImportRouteDescriptor.label,
    "/tenant/federated-identity-providers": "Tenant federation",
    "/tenant/groups": "Security groups",
    "/tenant/identity-providers": "Identity providers",
    "/tenant/mfa-policies": "Tenant MFA policies",
    "/tenant/notifications": "Notifications",
    "/tenant/operator-teams": "Operator teams",
    "/tenant/roles": "Roles",
    "/tenant/service-accounts": "Service accounts",
    "/tenant/settings": "Tenant identity",
    [ticketNumberingRouteDescriptor.path]: ticketNumberingRouteDescriptor.label,
    "/tenant/sla": "SLA administration",
    "/tenant/users": "Users",
    "/tenant/workflows": "Workflows",
  };
  const exact = exactTitles[path];
  if (exact) return exact;
  if (path.startsWith("/alerts/")) return "Alert detail";
  if (path.startsWith("/cases/")) return "Case detail";
  return "Workspace";
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
