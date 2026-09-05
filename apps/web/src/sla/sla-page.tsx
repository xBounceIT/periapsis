import { useSession } from "../auth/session-context";
import { useTenantAuthority } from "../auth/tenant-authority-context";
import { slaAdminApi, type SlaAdminApi } from "./sla-api";
import { SlaLoading } from "./sla-primitives";
import { TenantSlaWorkspace } from "./sla-workspace";

interface TenantSlaAdministrationPageProps {
  api?: SlaAdminApi;
}

export function TenantSlaAdministrationPage({
  api = slaAdminApi,
}: TenantSlaAdministrationPageProps = {}): React.JSX.Element {
  const { session } = useSession();
  const authority = useTenantAuthority();
  const tenantId = session.activeTenantId ?? "";

  if (tenantId && authority.status === "loading") {
    return (
      <div className="content">
        <SlaLoading label="Loading live SLA authority" />
      </div>
    );
  }

  const ready = Boolean(tenantId) && authority.status === "ready";
  return (
    <div className="content">
      <TenantSlaWorkspace
        api={api}
        canManage={ready && authority.hasPermission("sla.manage", "tenant")}
        canRead={ready && authority.hasPermission("sla.read", "tenant")}
        canSimulate={ready && authority.hasPermission("sla.simulate", "tenant")}
        csrfToken={session.csrfToken}
        tenantId={tenantId}
      />
    </div>
  );
}
