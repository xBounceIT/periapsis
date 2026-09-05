// oxlint-disable-next-line import/no-unassigned-import -- Registers the self-hosted primary font.
import "@fontsource-variable/archivo";
// oxlint-disable-next-line import/no-unassigned-import -- Registers the self-hosted telemetry font.
import "@fontsource/ibm-plex-mono/400.css";
// oxlint-disable-next-line import/no-unassigned-import -- Loads shared Tailwind and shadcn tokens.
import "@periapsis/ui/styles.css";
// oxlint-disable-next-line import/no-unassigned-import -- Loads shell-specific layout styles.
import "./app.css";

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { createBrowserRouter, Navigate, RouterProvider } from "react-router";

import { AppShell, ControlPlaneOverview } from "./app";
import { ApplicationBoundary } from "./auth/application-boundary";
import { mfaSecurityRouteDescriptor } from "./auth/mfa/model";
import {
  platformAuditRouteDescriptor,
  tenantAuditRouteDescriptor,
} from "./audit/model";
import { contactAdministrationRouteDescriptor } from "./contacts/model";
import { customFieldAdministrationRouteDescriptor } from "./customfields/model";
import { customFieldImportRouteDescriptor } from "./customfields/custom-field-import-model";
import { tenantFederationRouteDescriptor } from "./federation/model";
import { phaseTwoApi } from "./lib/phase-two-api";
import {
  platformMfaPolicyRouteDescriptor,
  tenantMfaPolicyRouteDescriptor,
} from "./mfapolicy/model";
import {
  platformSmtpRouteDescriptor,
  tenantNotificationRouteDescriptor,
} from "./notifications/model";
import { notificationInboxRouteDescriptor } from "./notifications/inbox-model";
import { customerPortalRouteDescriptor } from "./portal/model";
import { platformAuthProviderRouteDescriptor } from "./pages/platform-auth-provider-model";
import { platformLocalAccountRouteDescriptor } from "./pages/platform-local-account-model";
import { platformOperationsRouteDescriptor } from "./platform/platform-operations-model";
import { slaAdministrationRouteDescriptor } from "./sla/model";
import { tenantSettingsRouteDescriptor } from "./settings/model";
import { ticketNumberingRouteDescriptor } from "./settings/numbering/model";
import { workflowAdministrationRouteDescriptor } from "./workflows/model";
import { reportingRouteDescriptor } from "./ticketing/reporting-model";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 15_000,
    },
  },
});

const router = createBrowserRouter([
  {
    path: "/",
    element: <ApplicationBoundary api={phaseTwoApi} />,
    children: [
      {
        Component: AppShell,
        children: [
          { index: true, Component: ControlPlaneOverview },
          {
            path: "alerts",
            lazy: async () => ({
              Component: (await import("./ticketing/ticket-list-page"))
                .AlertListPage,
            }),
          },
          {
            path: "alerts/new",
            lazy: async () => ({
              Component: (await import("./ticketing/ticket-create-page"))
                .AlertCreatePage,
            }),
          },
          {
            path: "alerts/:alertId",
            lazy: async () => ({
              Component: (await import("./ticketing/ticket-detail-page"))
                .AlertDetailPage,
            }),
          },
          {
            path: "cases",
            lazy: async () => ({
              Component: (await import("./ticketing/ticket-list-page"))
                .CaseListPage,
            }),
          },
          {
            path: "cases/new",
            lazy: async () => ({
              Component: (await import("./ticketing/ticket-create-page"))
                .CaseCreatePage,
            }),
          },
          {
            path: "cases/:caseId",
            lazy: async () => ({
              Component: (await import("./ticketing/ticket-detail-page"))
                .CaseDetailPage,
            }),
          },
          {
            path: "search",
            lazy: async () => ({
              Component: (await import("./ticketing/global-search-page"))
                .GlobalSearchPage,
            }),
          },
          {
            path: "activity",
            lazy: async () => ({
              Component: (await import("./ticketing/global-activity-page"))
                .GlobalActivityPage,
            }),
          },
          {
            path: childRoutePath(reportingRouteDescriptor.path),
            lazy: async () => ({
              Component: (await import("./ticketing/reporting-page"))
                .ReportingPage,
            }),
          },
          {
            path: "profile",
            lazy: async () => ({
              Component: (await import("./pages/user-profile")).UserProfilePage,
            }),
          },
          {
            path: "sessions",
            lazy: async () => ({
              Component: (await import("./pages/sessions")).SessionsPage,
            }),
          },
          {
            path: childRoutePath(mfaSecurityRouteDescriptor.path),
            lazy: async () => ({
              Component: (await import("./auth/mfa/mfa-workspace"))
                .MfaSecurityWorkspace,
            }),
          },
          {
            path: childRoutePath(contactAdministrationRouteDescriptor.path),
            lazy: async () => ({
              Component: (
                await import("./contacts/contact-administration-page")
              ).ContactAdministrationPage,
            }),
          },
          {
            path: childRoutePath(customerPortalRouteDescriptor.path),
            lazy: async () => ({
              Component: (await import("./portal/customer-portal-page"))
                .CustomerPortalPage,
            }),
          },
          {
            path: childRoutePath(notificationInboxRouteDescriptor.path),
            lazy: async () => ({
              Component: (await import("./notifications/inbox-route"))
                .NotificationInboxRoute,
            }),
          },
          {
            path: childRoutePath(tenantNotificationRouteDescriptor.path),
            lazy: async () => ({
              Component: (await import("./pages/notification-administration"))
                .TenantNotificationAdministrationPage,
            }),
          },
          {
            path: childRoutePath(tenantSettingsRouteDescriptor.path),
            lazy: async () => ({
              Component: (await import("./settings/tenant-settings-page"))
                .TenantSettingsPage,
            }),
          },
          {
            path: childRoutePath(ticketNumberingRouteDescriptor.path),
            lazy: async () => ({
              Component: (
                await import("./settings/numbering/ticket-numbering-page")
              ).TicketNumberingPage,
            }),
          },
          {
            path: childRoutePath(platformSmtpRouteDescriptor.path),
            lazy: async () => ({
              Component: (await import("./pages/notification-administration"))
                .PlatformNotificationSmtpPage,
            }),
          },
          {
            path: childRoutePath(tenantAuditRouteDescriptor.path),
            lazy: async () => ({
              Component: (await import("./audit/audit-pages")).TenantAuditPage,
            }),
          },
          {
            path: childRoutePath(slaAdministrationRouteDescriptor.path),
            lazy: async () => ({
              Component: (await import("./sla/sla-page"))
                .TenantSlaAdministrationPage,
            }),
          },
          {
            path: childRoutePath(workflowAdministrationRouteDescriptor.path),
            lazy: async () => ({
              Component: (
                await import("./workflows/workflow-administration-page")
              ).TenantWorkflowAdministrationPage,
            }),
          },
          {
            path: childRoutePath(customFieldAdministrationRouteDescriptor.path),
            lazy: async () => ({
              Component: (
                await import("./customfields/custom-field-administration-page")
              ).TenantCustomFieldAdministrationPage,
            }),
          },
          {
            path: childRoutePath(customFieldImportRouteDescriptor.path),
            lazy: async () => ({
              Component: (
                await import("./customfields/custom-field-import-page")
              ).TenantCustomFieldImportPage,
            }),
          },
          {
            path: childRoutePath(tenantMfaPolicyRouteDescriptor.path),
            lazy: async () => ({
              Component: (await import("./mfapolicy/mfa-policy-admin-page"))
                .TenantMfaPolicyAdministrationPage,
            }),
          },
          {
            path: childRoutePath(platformAuditRouteDescriptor.path),
            lazy: async () => ({
              Component: (await import("./audit/audit-pages"))
                .PlatformAuditPage,
            }),
          },
          {
            path: "platform/tenants",
            lazy: async () => ({
              Component: (await import("./pages/platform-tenants"))
                .PlatformTenantsPage,
            }),
          },
          {
            path: childRoutePath(platformOperationsRouteDescriptor.path),
            lazy: async () => ({
              Component: (await import("./platform/platform-operations-page"))
                .PlatformOperationsPage,
            }),
          },
          {
            path: "platform/operator-teams",
            lazy: async () => ({
              Component: (await import("./pages/platform-operator-teams"))
                .PlatformOperatorTeamsPage,
            }),
          },
          {
            path: childRoutePath(platformAuthProviderRouteDescriptor.path),
            lazy: async () => ({
              Component: (await import("./pages/platform-auth-providers"))
                .PlatformAuthProvidersPage,
            }),
          },
          {
            path: childRoutePath(platformLocalAccountRouteDescriptor.path),
            lazy: async () => ({
              Component: (await import("./pages/platform-local-accounts"))
                .PlatformLocalAccountsPage,
            }),
          },
          {
            path: childRoutePath(platformMfaPolicyRouteDescriptor.path),
            lazy: async () => ({
              Component: (await import("./mfapolicy/mfa-policy-admin-page"))
                .PlatformMfaPolicyAdministrationPage,
            }),
          },
          {
            path: "tenant/roles",
            lazy: async () => ({
              Component: (await import("./pages/tenant-roles")).TenantRolesPage,
            }),
          },
          {
            path: "tenant/service-accounts",
            lazy: async () => ({
              Component: (await import("./pages/tenant-service-accounts"))
                .TenantServiceAccountsPage,
            }),
          },
          {
            path: "tenant/groups",
            lazy: async () => ({
              Component: (await import("./pages/tenant-groups"))
                .TenantGroupsPage,
            }),
          },
          {
            path: "tenant/identity-providers",
            lazy: async () => ({
              Component: (await import("./pages/tenant-ldap-providers"))
                .TenantLdapProvidersPage,
            }),
          },
          {
            path: childRoutePath(tenantFederationRouteDescriptor.path),
            lazy: async () => ({
              Component: (await import("./federation/tenant-federation-page"))
                .TenantFederationPage,
            }),
          },
          {
            path: "tenant/operator-teams",
            lazy: async () => ({
              Component: (await import("./pages/tenant-operator-teams"))
                .TenantOperatorTeamsPage,
            }),
          },
          {
            path: "tenant/users",
            lazy: async () => ({
              Component: (await import("./pages/tenant-users")).TenantUsersPage,
            }),
          },
          { path: "*", element: <Navigate to="/" replace /> },
        ],
      },
    ],
  },
]);

const root = document.querySelector("#root");
if (!root) {
  throw new Error("Periapsis root element is missing");
}

createRoot(root).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  </StrictMode>,
);

function childRoutePath(absolutePath: string): string {
  if (!absolutePath.startsWith("/") || absolutePath.length < 2) {
    throw new TypeError("Route descriptors must be absolute.");
  }
  return absolutePath.slice(1);
}
