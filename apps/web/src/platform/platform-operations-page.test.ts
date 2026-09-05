import { describe, expect, it } from "vitest";

import {
  platformFeatureFlagManagePermission,
  platformFeatureFlagReadPermission,
  platformOperationsReadPermission,
  platformSettingsManagePermission,
  platformSettingsReadPermission,
  platformUserReadPermission,
  type SessionView,
} from "../lib/phase-two-types";
import { sessionFixture } from "../test/phase-two-fixtures";
import { platformOperationsAuthority } from "./platform-operations-page";

const allPermissions = [
  platformFeatureFlagManagePermission,
  platformFeatureFlagReadPermission,
  platformOperationsReadPermission,
  platformSettingsManagePermission,
  platformSettingsReadPermission,
  platformUserReadPermission,
];

describe("platformOperationsAuthority", () => {
  it("projects permissions only for an explicitly tenantless session", () => {
    const tenantless: SessionView = {
      ...sessionFixture,
      permissions: allPermissions,
    };
    expect(platformOperationsAuthority(tenantless)).toEqual({
      canManageFeatureFlags: true,
      canManageSettings: true,
      canReadFeatureFlags: true,
      canReadOperations: true,
      canReadSettings: true,
      canReadUsers: true,
    });

    const tenantScoped: SessionView = {
      ...tenantless,
      activeTenantId: "019d4d16-2160-7000-8000-000000000099",
    };
    expect(platformOperationsAuthority(tenantScoped)).toEqual({
      canManageFeatureFlags: false,
      canManageSettings: false,
      canReadFeatureFlags: false,
      canReadOperations: false,
      canReadSettings: false,
      canReadUsers: false,
    });
  });
});
