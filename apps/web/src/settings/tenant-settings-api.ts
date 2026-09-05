import {
  getTenantSettings,
  updateTenantSettings,
  type TenantSettings,
} from "@periapsis/contracts";

import { PhaseTwoApiError } from "../lib/phase-two-types";
import { parseRfc3339Instant } from "../lib/rfc3339-instant";
import { sessionAwareFetch } from "../lib/session-transition-transport";
import { isCanonicalUuidV7 } from "../lib/uuid-v7";
import {
  isTenantSettingsProjection,
  tenantSettingsReasonIsValid,
  tenantSettingsUpdateRequest,
  type TenantSettingsApi,
  type VersionedTenantSettings,
} from "./model";

interface GeneratedResult<T> {
  data: T | undefined;
  error?: unknown;
  response?: Response;
}

interface SafeProblem {
  code?: string;
}

const strongEntityTagPattern = /^"v([1-9]\d{0,9})"$/u;

export const tenantSettingsApi: TenantSettingsApi = {
  async get(tenantId, signal) {
    requireTenantId(tenantId);
    const result = await getTenantSettings({
      ...requestDefaults(),
      cache: "no-store",
      path: { tenantId },
      ...(signal ? { signal } : {}),
    });
    return unwrapSettings(result, tenantId);
  },

  async update(csrfToken, tenantId, current, reason, draft, signal) {
    requireTenantId(tenantId);
    requireCsrf(csrfToken);
    if (
      current.value.tenantId !== tenantId ||
      !tenantSettingsReasonIsValid(reason) ||
      !isTenantSettingsProjection(current.value, tenantId) ||
      entityTagVersion(current.etag) !== current.value.version
    ) {
      throw new PhaseTwoApiError("The tenant settings command is invalid.");
    }
    const body = tenantSettingsUpdateRequest(current.value.version, draft);
    const result = await updateTenantSettings({
      ...requestDefaults(),
      body,
      cache: "no-store",
      headers: {
        "If-Match": current.etag,
        "X-Audit-Reason": reason,
        "X-CSRF-Token": csrfToken,
      },
      path: { tenantId },
      ...(signal ? { signal } : {}),
    });
    const updated = unwrapSettings(result, tenantId);
    const previousUpdatedAt = parseRfc3339Instant(current.value.updatedAt);
    const updatedAt = parseRfc3339Instant(updated.value.updatedAt);
    if (
      updated.value.version !== current.value.version + 1 ||
      previousUpdatedAt === undefined ||
      updatedAt === undefined ||
      updatedAt < previousUpdatedAt ||
      updated.value.brandName !== body.brandName ||
      updated.value.brandMark !== body.brandMark ||
      updated.value.primaryColor !== body.primaryColor ||
      updated.value.accentColor !== body.accentColor ||
      updated.value.timezone !== body.timezone ||
      updated.value.locale !== body.locale
    ) {
      throw projectionError();
    }
    return updated;
  },
};

function requestDefaults() {
  return {
    baseUrl: globalThis.location.origin,
    credentials: "same-origin" as const,
    fetch: sessionAwareFetch,
  };
}

function unwrapSettings(
  result: GeneratedResult<TenantSettings>,
  tenantId: string,
): VersionedTenantSettings {
  if (!result.response?.ok || result.response.status !== 200) {
    throw apiError(result.error, result.response);
  }
  requirePrivateNoStore(result.response);
  if (!isTenantSettingsProjection(result.data, tenantId)) {
    throw projectionError();
  }
  const etag = result.response.headers.get("ETag");
  if (!etag || entityTagVersion(etag) !== result.data.version) {
    throw projectionError();
  }
  return { etag, value: { ...result.data } };
}

function entityTagVersion(etag: string): number | undefined {
  const match = strongEntityTagPattern.exec(etag);
  if (!match?.[1]) return undefined;
  const version = Number(match[1]);
  return Number.isSafeInteger(version) && version <= 2_147_483_647
    ? version
    : undefined;
}

function requirePrivateNoStore(response: Response): void {
  const directives = response.headers
    .get("Cache-Control")
    ?.split(",")
    .map((directive) => directive.trim().toLowerCase());
  if (!directives?.includes("private") || !directives.includes("no-store")) {
    throw new PhaseTwoApiError(
      "The API did not mark tenant settings as private and no-store.",
      response.status,
    );
  }
}

function requireTenantId(tenantId: string): void {
  if (!isCanonicalUuidV7(tenantId)) {
    throw new PhaseTwoApiError("The tenant settings context is invalid.");
  }
}

function requireCsrf(csrfToken: string): void {
  if (
    csrfToken.length < 1 ||
    csrfToken.length > 128 ||
    csrfToken.trim() !== csrfToken ||
    csrfToken.includes(",")
  ) {
    throw new PhaseTwoApiError("The tenant settings CSRF context is invalid.");
  }
}

function projectionError(): PhaseTwoApiError {
  return new PhaseTwoApiError(
    "The API response did not match the requested tenant settings projection.",
    undefined,
    { code: "tenant_projection_mismatch" },
  );
}

function apiError(error: unknown, response?: Response): PhaseTwoApiError {
  const problem = safeProblem(error);
  const status = response?.status;
  const fallback =
    status === 412
      ? "Tenant settings changed after this form was loaded."
      : status === 403
        ? "The server denied access to tenant settings."
        : status === 401
          ? "The current session is no longer authenticated."
          : "Tenant settings could not be loaded.";
  return new PhaseTwoApiError(
    fallback,
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
