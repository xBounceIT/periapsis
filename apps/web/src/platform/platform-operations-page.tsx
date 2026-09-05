import { useSession } from "../auth/session-context";
import {
  describePhaseTwoError,
  hasPermission,
  platformFeatureFlagManagePermission,
  platformFeatureFlagReadPermission,
  platformOperationsReadPermission,
  platformSettingsManagePermission,
  platformSettingsReadPermission,
  platformUserReadPermission,
  type SessionView,
} from "../lib/phase-two-types";
import { platformOperationsApi } from "./platform-operations-api";
import type { PlatformOperationsAuthority } from "./platform-operations-model";
import { PlatformOperationsWorkspace } from "./platform-operations-workspace";

export function PlatformOperationsPage(): React.JSX.Element {
  const { session } = useSession();

  return (
    <div className="content">
      <PlatformOperationsWorkspace
        api={platformOperationsApi}
        authority={platformOperationsAuthority(session)}
        csrfToken={session.csrfToken}
        describeError={describePhaseTwoError}
        sessionKey={session.id}
      />
    </div>
  );
}

export function platformOperationsAuthority(
  session: SessionView,
): PlatformOperationsAuthority {
  const tenantless = session.activeTenantId === undefined;
  return {
    canManageFeatureFlags:
      tenantless && hasPermission(session, platformFeatureFlagManagePermission),
    canManageSettings:
      tenantless && hasPermission(session, platformSettingsManagePermission),
    canReadFeatureFlags:
      tenantless && hasPermission(session, platformFeatureFlagReadPermission),
    canReadOperations:
      tenantless && hasPermission(session, platformOperationsReadPermission),
    canReadSettings:
      tenantless && hasPermission(session, platformSettingsReadPermission),
    canReadUsers:
      tenantless && hasPermission(session, platformUserReadPermission),
  };
}
