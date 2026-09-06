import type { RouteObject } from "react-router";
import { TenantCustomFieldAdministrationPage } from "./custom-field-administration-page";
import { customFieldAdministrationRouteDescriptor } from "./model";
export const customFieldAdministrationRoutes = [
  {
    path: customFieldAdministrationRouteDescriptor.path.slice(1),
    Component: TenantCustomFieldAdministrationPage,
  },
] satisfies RouteObject[];
