export const platformFailedNotificationsFlag =
  "platform_failed_notifications_view" as const;
export const platformSettingsChangedEvent =
  "periapsis:platform-settings-changed";

export const platformOperationsRouteDescriptor = {
  label: "Platform operations",
  path: "/platform/operations",
  permissions: [
    "platform.user.read",
    "platform.operations.read",
    "platform.settings.read",
    "platform.feature_flag.read",
  ] as const,
};

export interface PlatformGlobalSettingsView {
  defaultLocale: string;
  defaultTimezone: string;
  platformName: string;
  supportUrl: string | null;
  updatedAt: string;
  version: number;
}

export interface PlatformFeatureFlagView {
  enabled: boolean;
  key: typeof platformFailedNotificationsFlag;
  updatedAt: string;
  version: number;
}

export interface PlatformHealthCheckView {
  failedCount?: number;
  key: "database" | "platform_audit_chain" | "queue_backlog" | "queue_failures";
  oldestPendingSeconds?: number;
  pendingCount?: number;
  status: "degraded" | "healthy";
}

export interface PlatformHealthView {
  checkedAt: string;
  checks: readonly PlatformHealthCheckView[];
  projectionVersion: 1;
  status: "degraded" | "healthy";
}

export interface PlatformQueueSourceView {
  failedCount: number;
  inFlightCount: number;
  key: string;
  oldestPendingSeconds: number;
  pendingCount: number;
}

export interface PlatformQueueSnapshotView {
  checkedAt: string;
  projectionVersion: 1;
  sources: readonly PlatformQueueSourceView[];
}

export interface PlatformUserView {
  active: boolean;
  activeTenantMembershipCount: number;
  displayName: string;
  email?: string;
  id: string;
  liveSessionsByAuthenticationMethod: readonly {
    liveSessionCount: number;
    method: string;
  }[];
  platformRoles: readonly string[];
  totalTenantMembershipCount: number;
}

export interface PlatformUserPageView {
  items: readonly PlatformUserView[];
  nextCursor?: string;
  projectionVersion: 1;
}

export interface PlatformFailedNotificationView {
  attemptCount: number;
  channel: "email" | "webhook";
  createdAt: string;
  failureAt: string;
  failureClass: string;
  failureCode: string;
  id: string;
  tenantId: string;
  updatedAt: string;
}

export interface PlatformFailedNotificationPageView {
  items: readonly PlatformFailedNotificationView[];
  nextCursor?: string;
  projectionVersion: 1;
}

export interface PlatformOperationsApi {
  getHealth(input: { signal?: AbortSignal }): Promise<PlatformHealthView>;
  getSettings(input: {
    signal?: AbortSignal;
  }): Promise<PlatformGlobalSettingsView>;
  listFailedNotifications(input: {
    after?: string;
    limit?: number;
    signal?: AbortSignal;
  }): Promise<PlatformFailedNotificationPageView>;
  listFeatureFlags(input: {
    signal?: AbortSignal;
  }): Promise<readonly PlatformFeatureFlagView[]>;
  listQueues(input: {
    signal?: AbortSignal;
  }): Promise<PlatformQueueSnapshotView>;
  listUsers(input: {
    after?: string;
    limit?: number;
    signal?: AbortSignal;
  }): Promise<PlatformUserPageView>;
  updateFeatureFlag(input: {
    body: {
      enabled: boolean;
      expectedVersion: number;
    };
    csrfToken: string;
    flagKey: typeof platformFailedNotificationsFlag;
    reason: string;
    signal?: AbortSignal;
  }): Promise<PlatformFeatureFlagView>;
  updateSettings(input: {
    body: {
      defaultLocale: string;
      defaultTimezone: string;
      expectedVersion: number;
      platformName: string;
      supportUrl: string | null;
    };
    csrfToken: string;
    reason: string;
    signal?: AbortSignal;
  }): Promise<PlatformGlobalSettingsView>;
}

export interface PlatformOperationsAuthority {
  canManageFeatureFlags: boolean;
  canManageSettings: boolean;
  canReadFeatureFlags: boolean;
  canReadOperations: boolean;
  canReadSettings: boolean;
  canReadUsers: boolean;
}
