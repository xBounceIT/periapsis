import type { RouteObject } from "react-router";

import { useSession } from "../auth/session-context";
import { useTenantAuthority } from "../auth/tenant-authority-context";
import {
  workflowAdministrationApi,
  type WorkflowAdministrationApi,
} from "./workflow-api";
import {
  workflowAdministrationRouteDescriptor,
  workflowManagePermission,
  workflowReadPermission,
} from "./model";
import { WorkflowWorkspace } from "./workflow-workspace";

interface WorkflowAdministrationPageProps {
  api?: WorkflowAdministrationApi;
}

export function TenantWorkflowAdministrationPage({
  api = workflowAdministrationApi,
}: WorkflowAdministrationPageProps = {}): React.JSX.Element {
  const { session } = useSession();
  const authority = useTenantAuthority();
  const tenantId = session.activeTenantId ?? "";

  if (tenantId && authority.status === "loading") {
    return (
      <div className="content" role="status" aria-live="polite">
        <section className="workflow-empty">
          <p className="section-label">Live authorization</p>
          <h1>Checking workflow authority…</h1>
          <p>
            The administration workspace remains closed until the current tenant
            projection is ready.
          </p>
        </section>
      </div>
    );
  }

  const ready = Boolean(tenantId) && authority.status === "ready";
  return (
    <div className="content">
      <WorkflowWorkspace
        api={api}
        canManage={
          ready && authority.hasPermission(workflowManagePermission, "tenant")
        }
        canRead={
          ready && authority.hasPermission(workflowReadPermission, "tenant")
        }
        csrfToken={session.csrfToken}
        tenantId={tenantId}
      />
    </div>
  );
}

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
