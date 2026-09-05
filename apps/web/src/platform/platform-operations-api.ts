import {
  getPlatformGlobalSettings,
  getPlatformOperationsHealth,
  listPlatformFailedNotifications,
  listPlatformFeatureFlags,
  listPlatformOperationQueues,
  listPlatformUsers,
  updatePlatformFeatureFlag,
  updatePlatformGlobalSettings,
  type PlatformFailedNotificationPage,
  type PlatformFeatureFlag,
  type PlatformFeatureFlagList,
  type PlatformGlobalSettings,
  type PlatformOperationQueueSnapshot,
  type PlatformOperationsHealth,
  type PlatformUserPage,
} from "@periapsis/contracts";

import { PhaseTwoApiError } from "../lib/phase-two-types";
import { sessionAwareFetch } from "../lib/session-transition-transport";
import { isCanonicalUuidV7 } from "../lib/uuid-v7";
import {
  platformFailedNotificationsFlag,
  type PlatformFailedNotificationPageView,
  type PlatformFeatureFlagView,
  type PlatformGlobalSettingsView,
  type PlatformHealthView,
  type PlatformOperationsApi,
  type PlatformQueueSnapshotView,
  type PlatformUserPageView,
} from "./platform-operations-model";

interface GeneratedResult<T> {
  data?: T | undefined;
  error?: unknown;
  response?: Response;
}

interface SafeProblem {
  code?: string;
}

const strongEntityTagPattern = /^"v([1-9]\d{0,9})"$/u;
const opaqueCursorPattern = /^[A-Za-z0-9_-]{1,512}$/u;
const localePattern = /^[a-z]{2,3}(?:-[A-Z]{2})?$/u;
const safeReasonPattern =
  /^[\x21-\x2b\x2d-\x7e](?:[\x20-\x2b\x2d-\x7e]*[\x21-\x2b\x2d-\x7e])?$/u;
const authenticationMethods = new Set([
  "bootstrap_totp",
  "ldap",
  "oidc",
  "passkey",
  "recovery_code",
  "saml",
  "totp",
]);
const queueKeys = [
  "outbox",
  "notification_delivery",
  "ticket_bulk",
  "ticket_export",
  "ticket_export_cleanup",
  "tenant_audit_export",
  "platform_audit_export",
  "sla_evaluation",
  "sla_trigger_action",
  "sla_event_ingress",
  "dfir_evidence_scan",
  "dfir_evidence_cleanup",
  "ldap_sync",
] as const;
const healthKeys = [
  "database",
  "platform_audit_chain",
  "queue_backlog",
  "queue_failures",
] as const;
const failureClasses = new Set([
  "authentication",
  "connectivity",
  "rate_limited",
  "render",
  "security",
  "timeout",
  "tls",
  "unknown",
  "submission_uncertain",
]);
const failureCodes = new Set([
  "retry_scheduled",
  "terminal_failure",
  "submission_uncertain",
  "configuration_revoked",
  "tenant_suspended",
  "unknown",
]);

const requestDefaults = {
  baseUrl: globalThis.location.origin,
  cache: "no-store" as const,
  credentials: "same-origin" as const,
  fetch: sessionAwareFetch,
};

export const platformOperationsApi: PlatformOperationsApi = {
  async getHealth(input) {
    const result = await getPlatformOperationsHealth({
      ...requestDefaults,
      ...(input.signal ? { signal: input.signal } : {}),
    });
    return projectHealth(unwrap(result));
  },

  async getSettings(input) {
    const result = await getPlatformGlobalSettings({
      ...requestDefaults,
      ...(input.signal ? { signal: input.signal } : {}),
    });
    const settings = projectSettings(unwrap(result));
    requireVersionETag(result.response, settings.version);
    return settings;
  },

  async listFailedNotifications(input) {
    if (input.after !== undefined && !opaqueCursorPattern.test(input.after)) {
      throw invalid("The failed notification cursor is invalid.");
    }
    requireLimit(input.limit);
    const result = await listPlatformFailedNotifications({
      ...requestDefaults,
      query: {
        ...(input.after === undefined ? {} : { after: input.after }),
        ...(input.limit === undefined ? {} : { limit: input.limit }),
      },
      ...(input.signal ? { signal: input.signal } : {}),
    });
    const page = projectFailedNotificationPage(unwrap(result));
    if (
      input.after !== undefined &&
      page.items[0] !== undefined &&
      !failedTupleBefore(page.items[0], decodeFailedCursor(input.after))
    ) {
      throw projectionError();
    }
    return page;
  },

  async listFeatureFlags(input) {
    const result = await listPlatformFeatureFlags({
      ...requestDefaults,
      ...(input.signal ? { signal: input.signal } : {}),
    });
    return projectFeatureFlagList(unwrap(result)).items;
  },

  async listQueues(input) {
    const result = await listPlatformOperationQueues({
      ...requestDefaults,
      ...(input.signal ? { signal: input.signal } : {}),
    });
    return projectQueues(unwrap(result));
  },

  async listUsers(input) {
    if (input.after !== undefined && !isCanonicalUuidV7(input.after)) {
      throw invalid("The platform user cursor is invalid.");
    }
    requireLimit(input.limit);
    const result = await listPlatformUsers({
      ...requestDefaults,
      query: {
        ...(input.after === undefined ? {} : { after: input.after }),
        ...(input.limit === undefined ? {} : { limit: input.limit }),
      },
      ...(input.signal ? { signal: input.signal } : {}),
    });
    const page = projectUserPage(unwrap(result));
    if (
      input.after !== undefined &&
      page.items[0] !== undefined &&
      page.items[0].id <= input.after
    ) {
      throw projectionError();
    }
    return page;
  },

  async updateFeatureFlag(input) {
    requireMutation(input.csrfToken, input.reason, input.body.expectedVersion);
    if (input.flagKey !== platformFailedNotificationsFlag) {
      throw invalid("The feature flag is not allowlisted.");
    }
    const result = await updatePlatformFeatureFlag({
      ...requestDefaults,
      body: input.body,
      headers: mutationHeaders(
        input.csrfToken,
        input.reason,
        input.body.expectedVersion,
      ),
      path: { flagKey: input.flagKey },
      ...(input.signal ? { signal: input.signal } : {}),
    });
    const flag = projectFeatureFlag(unwrap(result));
    requireVersionETag(result.response, flag.version);
    if (
      flag.key !== input.flagKey ||
      flag.enabled !== input.body.enabled ||
      flag.version !== input.body.expectedVersion + 1
    ) {
      throw projectionError();
    }
    return flag;
  },

  async updateSettings(input) {
    requireMutation(input.csrfToken, input.reason, input.body.expectedVersion);
    const result = await updatePlatformGlobalSettings({
      ...requestDefaults,
      body: input.body,
      headers: mutationHeaders(
        input.csrfToken,
        input.reason,
        input.body.expectedVersion,
      ),
      ...(input.signal ? { signal: input.signal } : {}),
    });
    const settings = projectSettings(unwrap(result));
    requireVersionETag(result.response, settings.version);
    if (
      settings.version !== input.body.expectedVersion + 1 ||
      settings.platformName !== input.body.platformName ||
      settings.defaultLocale !== input.body.defaultLocale ||
      settings.defaultTimezone !== input.body.defaultTimezone ||
      settings.supportUrl !== input.body.supportUrl
    ) {
      throw projectionError();
    }
    return settings;
  },
};

function unwrap<T>(result: GeneratedResult<T>): T {
  const data = result.data;
  if (
    !result.response?.ok ||
    result.response.status !== 200 ||
    data === undefined
  ) {
    throw apiError(result.error, result.response);
  }
  requireNoStore(result.response);
  return data;
}

function projectSettings(
  value: PlatformGlobalSettings,
): PlatformGlobalSettingsView {
  if (
    !safeText(value.platformName, 1, 120) ||
    !localePattern.test(value.defaultLocale) ||
    !safeText(value.defaultTimezone, 1, 64) ||
    value.defaultTimezone === "Local" ||
    !positiveVersion(value.version) ||
    !validInstant(value.updatedAt) ||
    (value.supportUrl !== null && !safeHTTPSURL(value.supportUrl))
  ) {
    throw projectionError();
  }
  return { ...value };
}

function projectFeatureFlag(
  value: PlatformFeatureFlag,
): PlatformFeatureFlagView {
  if (
    value.key !== platformFailedNotificationsFlag ||
    !positiveVersion(value.version) ||
    !validInstant(value.updatedAt)
  ) {
    throw projectionError();
  }
  return { ...value };
}

function projectFeatureFlagList(value: PlatformFeatureFlagList): {
  items: readonly PlatformFeatureFlagView[];
} {
  if (value.projectionVersion !== 1 || value.items.length !== 1) {
    throw projectionError();
  }
  return { items: value.items.map(projectFeatureFlag) };
}

function projectUserPage(value: PlatformUserPage): PlatformUserPageView {
  if (
    value.projectionVersion !== 1 ||
    value.items.length > 100 ||
    (value.nextCursor !== null && !isCanonicalUuidV7(value.nextCursor))
  ) {
    throw projectionError();
  }
  let previous = "";
  const items = value.items.map((user) => {
    if (
      !isCanonicalUuidV7(user.id) ||
      (previous !== "" && previous >= user.id) ||
      !safeText(user.displayName, 1, 256) ||
      (user.email !== null && !safeText(user.email, 3, 320)) ||
      !nonnegativeInteger(user.activeTenantMembershipCount) ||
      !nonnegativeInteger(user.totalTenantMembershipCount) ||
      user.activeTenantMembershipCount > user.totalTenantMembershipCount ||
      !strictSorted(user.platformRoles) ||
      !strictSorted(
        user.liveSessionsByAuthenticationMethod.map(({ method }) => method),
      ) ||
      user.liveSessionsByAuthenticationMethod.some(
        ({ liveSessionCount, method }) =>
          !authenticationMethods.has(method) ||
          !positiveInteger(liveSessionCount),
      )
    ) {
      throw projectionError();
    }
    previous = user.id;
    return {
      active: user.active,
      activeTenantMembershipCount: user.activeTenantMembershipCount,
      displayName: user.displayName,
      ...(user.email === null ? {} : { email: user.email }),
      id: user.id,
      liveSessionsByAuthenticationMethod:
        user.liveSessionsByAuthenticationMethod.map((summary) => ({
          ...summary,
        })),
      platformRoles: [...user.platformRoles],
      totalTenantMembershipCount: user.totalTenantMembershipCount,
    };
  });
  if (
    value.nextCursor !== null &&
    (items.length === 0 || value.nextCursor !== items.at(-1)?.id)
  ) {
    throw projectionError();
  }
  return {
    items,
    ...(value.nextCursor === null ? {} : { nextCursor: value.nextCursor }),
    projectionVersion: 1,
  };
}

function projectQueues(
  value: PlatformOperationQueueSnapshot,
): PlatformQueueSnapshotView {
  if (
    value.projectionVersion !== 1 ||
    !validInstant(value.checkedAt) ||
    value.sources.length !== queueKeys.length
  ) {
    throw projectionError();
  }
  return {
    checkedAt: value.checkedAt,
    projectionVersion: 1,
    sources: value.sources.map((source, index) => {
      if (
        source.key !== queueKeys[index] ||
        !nonnegativeInteger(source.pendingCount) ||
        !nonnegativeInteger(source.inFlightCount) ||
        !nonnegativeInteger(source.failedCount) ||
        !nonnegativeInteger(source.oldestPendingSeconds)
      ) {
        throw projectionError();
      }
      return { ...source };
    }),
  };
}

function projectHealth(value: PlatformOperationsHealth): PlatformHealthView {
  if (
    value.projectionVersion !== 1 ||
    !validInstant(value.checkedAt) ||
    !healthStatus(value.status) ||
    value.checks.length !== healthKeys.length
  ) {
    throw projectionError();
  }
  const checks = value.checks.map((check, index) => {
    if (
      check.key !== healthKeys[index] ||
      !healthStatus(check.status) ||
      !validHealthCheckShape(index, check)
    ) {
      throw projectionError();
    }
    return { ...check };
  });
  if (
    (value.status === "degraded") !==
    checks.some(({ status }) => status === "degraded")
  ) {
    throw projectionError();
  }
  return { ...value, checks };
}

function projectFailedNotificationPage(
  value: PlatformFailedNotificationPage,
): PlatformFailedNotificationPageView {
  if (
    value.projectionVersion !== 1 ||
    value.items.length > 100 ||
    (value.nextCursor !== null && !opaqueCursorPattern.test(value.nextCursor))
  ) {
    throw projectionError();
  }
  let previous: PlatformFailedNotificationPageView["items"][number] | undefined;
  const items = value.items.map((item) => {
    if (
      !isCanonicalUuidV7(item.id) ||
      !isCanonicalUuidV7(item.tenantId) ||
      (item.channel !== "email" && item.channel !== "webhook") ||
      !failureClasses.has(item.failureClass) ||
      !failureCodes.has(item.failureCode) ||
      !validInstant(item.failureAt) ||
      !validInstant(item.createdAt) ||
      !validInstant(item.updatedAt) ||
      Date.parse(item.createdAt) > Date.parse(item.failureAt) ||
      Date.parse(item.failureAt) > Date.parse(item.updatedAt) ||
      !nonnegativeInteger(item.attemptCount)
    ) {
      throw projectionError();
    }
    const projected = { ...item };
    if (previous !== undefined && !failedTupleBefore(projected, previous)) {
      throw projectionError();
    }
    previous = projected;
    return projected;
  });
  if (value.nextCursor !== null) {
    const cursor = decodeFailedCursor(value.nextCursor);
    const last = items.at(-1);
    if (
      last === undefined ||
      cursor.id !== last.id ||
      Date.parse(cursor.failureAt) !== Date.parse(last.failureAt)
    ) {
      throw projectionError();
    }
  }
  return {
    items,
    ...(value.nextCursor === null ? {} : { nextCursor: value.nextCursor }),
    projectionVersion: 1,
  };
}

function requireMutation(
  csrfToken: string,
  reason: string,
  expectedVersion: number,
): void {
  if (
    csrfToken.length < 1 ||
    csrfToken.length > 128 ||
    csrfToken.trim() !== csrfToken ||
    csrfToken.includes(",") ||
    !safeReasonPattern.test(reason) ||
    !positiveVersion(expectedVersion) ||
    expectedVersion >= 2_147_483_647
  ) {
    throw invalid("The platform mutation context is invalid.");
  }
}

function mutationHeaders(
  csrfToken: string,
  reason: string,
  expectedVersion: number,
) {
  return {
    "If-Match": `"v${expectedVersion}"`,
    "X-Audit-Reason": reason,
    "X-CSRF-Token": csrfToken,
  };
}

function requireLimit(limit: number | undefined): void {
  if (
    limit !== undefined &&
    (!Number.isInteger(limit) || limit < 1 || limit > 100)
  ) {
    throw invalid("The requested page size is invalid.");
  }
}

function requireVersionETag(
  response: Response | undefined,
  version: number,
): void {
  const etag = response?.headers.get("ETag");
  const match = etag ? strongEntityTagPattern.exec(etag) : null;
  if (!match?.[1] || Number(match[1]) !== version) {
    throw projectionError();
  }
}

function requireNoStore(response: Response): void {
  const directives = response.headers
    .get("Cache-Control")
    ?.split(",")
    .map((directive) => directive.trim().toLowerCase());
  if (!directives?.includes("no-store")) {
    throw new PhaseTwoApiError(
      "The platform projection was not marked no-store.",
      response.status,
    );
  }
}

function safeHTTPSURL(value: string): boolean {
  try {
    const url = new URL(value);
    return (
      url.protocol === "https:" && url.username === "" && url.password === ""
    );
  } catch {
    return false;
  }
}

function safeText(value: string, minimum: number, maximum: number): boolean {
  return (
    value === value.trim() &&
    Array.from(value).length >= minimum &&
    Array.from(value).length <= maximum &&
    !/[\p{Cc}\p{Cf}]/u.test(value)
  );
}

function strictSorted(values: readonly string[]): boolean {
  return values.every(
    (value, index) =>
      safeText(value, 1, 128) &&
      (index === 0 || (values[index - 1] ?? "") < value),
  );
}

function positiveVersion(value: number): boolean {
  return Number.isInteger(value) && value >= 1 && value <= 2_147_483_647;
}

function positiveInteger(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 1;
}

function nonnegativeInteger(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 0;
}

function validHealthCheckShape(
  index: number,
  check: PlatformOperationsHealth["checks"][number],
): boolean {
  if (index === 0 || index === 1) {
    return (
      check.pendingCount === undefined &&
      check.failedCount === undefined &&
      check.oldestPendingSeconds === undefined
    );
  }
  if (index === 2) {
    return (
      nonnegativeInteger(check.pendingCount ?? -1) &&
      check.failedCount === undefined &&
      nonnegativeInteger(check.oldestPendingSeconds ?? -1)
    );
  }
  return (
    index === 3 &&
    check.pendingCount === undefined &&
    nonnegativeInteger(check.failedCount ?? -1) &&
    check.oldestPendingSeconds === undefined
  );
}

interface FailedCursorProjection {
  failureAt: string;
  id: string;
}

function decodeFailedCursor(value: string): FailedCursorProjection {
  try {
    const base64 = value.replaceAll("-", "+").replaceAll("_", "/");
    const padding = "=".repeat((4 - (base64.length % 4)) % 4);
    const decoded = JSON.parse(globalThis.atob(base64 + padding)) as unknown;
    if (
      decoded === null ||
      typeof decoded !== "object" ||
      Object.keys(decoded).toSorted().join(",") !== "failureAt,id,v" ||
      !("v" in decoded) ||
      decoded.v !== 1 ||
      !("failureAt" in decoded) ||
      typeof decoded.failureAt !== "string" ||
      !validInstant(decoded.failureAt) ||
      !("id" in decoded) ||
      typeof decoded.id !== "string" ||
      !isCanonicalUuidV7(decoded.id)
    ) {
      throw projectionError();
    }
    return { failureAt: decoded.failureAt, id: decoded.id };
  } catch (error) {
    if (error instanceof PhaseTwoApiError) throw error;
    throw invalid("The failed notification cursor is invalid.");
  }
}

function failedTupleBefore(
  current: PlatformFailedNotificationPageView["items"][number],
  previous: FailedCursorProjection,
): boolean {
  const currentTime = Date.parse(current.failureAt);
  const previousTime = Date.parse(previous.failureAt);
  return (
    currentTime < previousTime ||
    (currentTime === previousTime && current.id < previous.id)
  );
}

function validInstant(value: string): boolean {
  return typeof value === "string" && Number.isFinite(Date.parse(value));
}

function healthStatus(value: string): value is "degraded" | "healthy" {
  return value === "degraded" || value === "healthy";
}

function projectionError(): PhaseTwoApiError {
  return new PhaseTwoApiError(
    "The API response did not match the redacted platform operations projection.",
    undefined,
    { code: "platform_projection_mismatch" },
  );
}

function invalid(message: string): PhaseTwoApiError {
  return new PhaseTwoApiError(message);
}

function apiError(error: unknown, response?: Response): PhaseTwoApiError {
  const problem = safeProblem(error);
  const status = response?.status;
  const message =
    status === 412
      ? "The platform resource changed after it was loaded."
      : status === 403
        ? "The server denied this platform operation."
        : status === 401
          ? "The current session is no longer authenticated."
          : "The platform operation could not be completed.";
  return new PhaseTwoApiError(
    message,
    status,
    problem?.code ? { code: problem.code } : undefined,
  );
}

function safeProblem(value: unknown): SafeProblem | null {
  if (
    value === null ||
    typeof value !== "object" ||
    !("code" in value) ||
    typeof value.code !== "string" ||
    !/^[a-z][a-z0-9_]{0,63}$/u.test(value.code)
  ) {
    return null;
  }
  return { code: value.code };
}
