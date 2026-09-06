import { customFieldImportRouteDescriptor } from "./customfields/custom-field-import-model";
import { notificationInboxRouteDescriptor } from "./notifications/inbox-model";
import { ticketNumberingRouteDescriptor } from "./settings/numbering/model";
import { reportingRouteDescriptor } from "./ticketing/reporting-model";

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
