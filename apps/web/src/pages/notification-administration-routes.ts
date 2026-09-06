import type { RouteObject } from "react-router";
import {
  platformSmtpRouteDescriptor,
  tenantNotificationRouteDescriptor,
} from "../notifications/model";
import {
  PlatformNotificationSmtpPage,
  TenantNotificationAdministrationPage,
} from "./notification-administration";
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
function childRoutePath(absolutePath: string): string {
  if (!absolutePath.startsWith("/") || absolutePath.length < 2) {
    throw new TypeError("Notification route descriptors must be absolute.");
  }
  return absolutePath.slice(1);
}
