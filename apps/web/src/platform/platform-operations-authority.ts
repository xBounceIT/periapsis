import {
  hasPermission,
  platformFeatureFlagManagePermission,
  platformFeatureFlagReadPermission,
  platformOperationsReadPermission,
  platformSettingsManagePermission,
  platformSettingsReadPermission,
  platformUserReadPermission,
  type SessionView,
} from "../lib/phase-two-types";
import type { PlatformOperationsAuthority } from "./platform-operations-model";

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
