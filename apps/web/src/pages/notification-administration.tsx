import type { RouteObject } from "react-router";
import {
  Alert,
  AlertDescription,
  AlertTitle,
} from "@periapsis/ui/components/ui/alert";
import { ShieldX } from "lucide-react";

import { useSession } from "../auth/session-context";
import { useTenantAuthority } from "../auth/tenant-authority-context";
import { hasPermission } from "../lib/phase-two-types";
import {
  notificationAdminApi,
  platformNotificationPermission,
  platformSmtpRouteDescriptor,
  tenantNotificationPermission,
  tenantNotificationRouteDescriptor,
  PlatformSmtpWorkspace,
  TenantNotificationWorkspace,
  type NotificationAdminApi,
} from "../notifications";

interface NotificationPageProps {
  api?: NotificationAdminApi;
}

export function TenantNotificationAdministrationPage({
  api = notificationAdminApi,
}: NotificationPageProps): React.JSX.Element {
  const { session } = useSession();
  const authority = useTenantAuthority();
  const tenantId = session.activeTenantId;

  if (!tenantId) {
    return (
      <NotificationRouteDenied
        boundary="tenant"
        reason="An active tenant is required before notification administration can be authorized."
      />
    );
  }
  if (authority.status === "loading") {
    return <NotificationAuthorityLoading boundary="tenant" />;
  }
  if (
    authority.status !== "ready" ||
    !authority.hasPermission(tenantNotificationPermission, "tenant")
  ) {
    return (
      <NotificationRouteDenied
        boundary="tenant"
        reason="The live tenant authority did not return notification.manage."
      />
    );
  }

  return (
    <div className="content">
      <TenantNotificationWorkspace
        api={api}
        canManage
        csrfToken={session.csrfToken}
        tenantId={tenantId}
      />
    </div>
  );
}

export function PlatformNotificationSmtpPage({
  api = notificationAdminApi,
}: NotificationPageProps): React.JSX.Element {
  const { session } = useSession();
  if (!hasPermission(session, platformNotificationPermission)) {
    return (
      <NotificationRouteDenied
        boundary="platform"
        reason="The current session did not return platform.notification.manage."
      />
    );
  }
  return (
    <div className="content">
      <PlatformSmtpWorkspace
        api={api}
        canManage
        csrfToken={session.csrfToken}
      />
    </div>
  );
}

export const notificationAdministrationRoutes = [
  {
    path: childRoutePath(tenantNotificationRouteDescriptor.path),
    Component: TenantNotificationAdministrationPage,
  },
  {
    path: childRoutePath(platformSmtpRouteDescriptor.path),
    Component: PlatformNotificationSmtpPage,
  },
] satisfies RouteObject[];

function NotificationAuthorityLoading({
  boundary,
}: {
  boundary: "tenant";
}): React.JSX.Element {
  return (
    <div className="content content--narrow" role="status" aria-live="polite">
      <section className="page-heading">
        <div>
          <p className="section-label">Live authorization</p>
          <h1>Checking notification authority…</h1>
          <p>
            The {boundary} workspace remains closed until the current server
            projection is ready.
          </p>
        </div>
      </section>
    </div>
  );
}

function NotificationRouteDenied({
  boundary,
  reason,
}: {
  boundary: "platform" | "tenant";
  reason: string;
}): React.JSX.Element {
  return (
    <div className="content content--narrow">
      <section
        className="page-heading"
        aria-labelledby={`${boundary}-notification-denied-title`}
      >
        <div>
          <p className="section-label">Live authorization decision</p>
          <h1 id={`${boundary}-notification-denied-title`}>
            Notification administration is unavailable.
          </h1>
          <p>{reason}</p>
        </div>
      </section>
      <Alert variant="destructive">
        <ShieldX aria-hidden="true" />
        <AlertTitle>Explicit permission required</AlertTitle>
        <AlertDescription>
          Navigation visibility is only a convenience. The {boundary} backend
          remains the authority for direct links and every operation.
        </AlertDescription>
      </Alert>
    </div>
  );
}

function childRoutePath(absolutePath: string): string {
  if (!absolutePath.startsWith("/") || absolutePath.length < 2) {
    throw new TypeError("Notification route descriptors must be absolute.");
  }
  return absolutePath.slice(1);
}
