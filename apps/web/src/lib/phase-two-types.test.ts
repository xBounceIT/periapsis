import { describe, expect, it } from "vitest";

import {
  platformAuditExportPermission,
  platformAuditReadPermission,
  platformAuditRetentionManagePermission,
  platformFeatureFlagManagePermission,
  platformFeatureFlagReadPermission,
  platformIdentityAccountManagePermission,
  platformIdentityAccountReadPermission,
  platformIdentityBindingManagePermission,
  platformIdentityBindingReadPermission,
  platformIdentityPolicyManagePermission,
  platformIdentityPolicyReadPermission,
  platformIdentityProviderManagePermission,
  platformIdentityProviderReadPermission,
  platformIdentityProviderTestPermission,
  platformNotificationManagePermission,
  platformOperatorTeamManagePermission,
  platformOperatorTeamReadPermission,
  platformOperationsReadPermission,
  platformPermissionKeys,
  platformTenantCreatePermission,
  platformTenantAccessPermission,
  platformTenantManagePermission,
  platformTenantReadPermission,
  platformSettingsManagePermission,
  platformSettingsReadPermission,
  platformUserReadPermission,
} from "./phase-two-types";

describe("platform permission catalog", () => {
  it("is a closed, duplicate-free set with named constants", () => {
    const namedPermissions = [
      platformTenantReadPermission,
      platformTenantCreatePermission,
      platformTenantManagePermission,
      platformTenantAccessPermission,
      platformOperatorTeamReadPermission,
      platformOperatorTeamManagePermission,
      platformIdentityProviderReadPermission,
      platformIdentityProviderManagePermission,
      platformIdentityProviderTestPermission,
      platformIdentityBindingReadPermission,
      platformIdentityBindingManagePermission,
      platformIdentityPolicyReadPermission,
      platformIdentityPolicyManagePermission,
      platformIdentityAccountReadPermission,
      platformIdentityAccountManagePermission,
      platformNotificationManagePermission,
      platformAuditReadPermission,
      platformAuditExportPermission,
      platformAuditRetentionManagePermission,
      platformUserReadPermission,
      platformOperationsReadPermission,
      platformSettingsReadPermission,
      platformSettingsManagePermission,
      platformFeatureFlagReadPermission,
      platformFeatureFlagManagePermission,
    ];

    expect(platformPermissionKeys).toEqual(namedPermissions);
    expect(new Set(platformPermissionKeys).size).toBe(
      platformPermissionKeys.length,
    );
  });
});
