import type { RouteObject } from "react-router";
import { customFieldImportRouteDescriptor } from "./custom-field-import-model";
import { TenantCustomFieldImportPage } from "./custom-field-import-page";
export const customFieldImportRoutes = [
  {
    path: customFieldImportRouteDescriptor.path.slice(1),
    Component: TenantCustomFieldImportPage,
  },
] satisfies RouteObject[];
