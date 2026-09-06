import { useSession } from "../auth/session-context";
import { useTenantAuthority } from "../auth/tenant-authority-context";
import { workflowManagePermission, workflowReadPermission } from "./model";
import {
  workflowAdministrationApi,
  type WorkflowAdministrationApi,
} from "./workflow-api";
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
