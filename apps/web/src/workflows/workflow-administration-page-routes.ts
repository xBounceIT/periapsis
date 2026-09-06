import type { RouteObject } from "react-router";
import { workflowAdministrationRouteDescriptor } from "./model";
import { TenantWorkflowAdministrationPage } from "./workflow-administration-page";
export const workflowAdministrationRoutes = [
  {
    path: childRoutePath(workflowAdministrationRouteDescriptor.path),
    Component: TenantWorkflowAdministrationPage,
  },
] satisfies RouteObject[];
function childRoutePath(absolutePath: string): string {
  if (!absolutePath.startsWith("/") || absolutePath.length < 2) {
    throw new TypeError("Workflow route descriptors must be absolute.");
  }
  return absolutePath.slice(1);
}
