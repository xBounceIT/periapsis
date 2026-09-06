import type {
  TenantSettings,
  TenantSettingsUpdateRequest,
} from "@periapsis/contracts";

import { parseRfc3339Instant } from "../lib/rfc3339-instant";
import { isCanonicalUuidV7 } from "../lib/uuid-v7";

export const tenantSettingsRouteDescriptor = {
  path: "/tenant/settings",
  label: "Tenant identity",
  permissions: ["settings.read"] as const,
};

export const tenantSettingsReadPermission = "settings.read" as const;
export const tenantSettingsManagePermission = "settings.manage" as const;
export const tenantSettingsChangedEvent =
  "periapsis:tenant-settings-changed" as const;

export interface VersionedTenantSettings {
  etag: string;
  value: TenantSettings;
}

export interface TenantSettingsDraft {
  accentColor: string;
  brandMark: string;
  brandName: string;
  locale: string;
  primaryColor: string;
  timezone: string;
}

export interface TenantSettingsApi {
  get(tenantId: string, signal?: AbortSignal): Promise<VersionedTenantSettings>;
  update(
    csrfToken: string,
    tenantId: string,
    current: VersionedTenantSettings,
    reason: string,
    draft: TenantSettingsDraft,
    signal?: AbortSignal,
  ): Promise<VersionedTenantSettings>;
}

export function tenantSettingsQueryKey(sessionId: string, tenantId: string) {
  return ["tenant-settings", sessionId, tenantId] as const;
}

export type TenantSettingsField = keyof TenantSettingsDraft;
export type TenantSettingsFieldErrors = Partial<
  Readonly<Record<TenantSettingsField, string>>
>;

const brandMarkPattern = /^[A-Z0-9]{1,4}$/u;
const colorPattern = /^#[0-9a-f]{6}$/u;
const localePattern = /^(?!und(?:-|$))[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*$/u;
const timezonePattern = /^(?!Local$)[A-Za-z0-9._+-]+(?:\/[A-Za-z0-9._+-]+)*$/u;

export function tenantSettingsDraftFrom(
  settings: TenantSettings,
): TenantSettingsDraft {
  return {
    accentColor: settings.accentColor,
    brandMark: settings.brandMark,
    brandName: settings.brandName,
    locale: settings.locale,
    primaryColor: settings.primaryColor,
    timezone: settings.timezone,
  };
}

export function tenantSettingsDraftDiffers(
  settings: TenantSettings,
  draft: TenantSettingsDraft,
): boolean {
  const normalized = normalizeTenantSettingsDraft(draft);
  return (
    normalized.accentColor !== settings.accentColor ||
    normalized.brandMark !== settings.brandMark ||
    normalized.brandName !== settings.brandName ||
    normalized.locale !== settings.locale ||
    normalized.primaryColor !== settings.primaryColor ||
    normalized.timezone !== settings.timezone
  );
}

export function normalizeTenantSettingsDraft(
  draft: TenantSettingsDraft,
): TenantSettingsDraft {
  return {
    accentColor: draft.accentColor.trim().toLowerCase(),
    brandMark: draft.brandMark.trim().toUpperCase(),
    brandName: draft.brandName.trim(),
    locale: draft.locale.trim(),
    primaryColor: draft.primaryColor.trim().toLowerCase(),
    timezone: draft.timezone.trim(),
  };
}

export function tenantSettingsDraftErrors(
  draft: TenantSettingsDraft,
): TenantSettingsFieldErrors {
  const normalized = normalizeTenantSettingsDraft(draft);
  const errors: Partial<Record<TenantSettingsField, string>> = {};
  if (
    normalized.brandName.length < 1 ||
    Array.from(normalized.brandName).length > 80 ||
    /[\p{Cc}\p{Cf}]/u.test(normalized.brandName)
  ) {
    errors.brandName = "Use 1–80 visible characters.";
  }
  if (!brandMarkPattern.test(normalized.brandMark)) {
    errors.brandMark = "Use 1–4 uppercase letters or digits.";
  }
  if (!colorPattern.test(normalized.primaryColor)) {
    errors.primaryColor = "Use a lowercase six-digit hex color.";
  }
  if (!colorPattern.test(normalized.accentColor)) {
    errors.accentColor = "Use a lowercase six-digit hex color.";
  } else if (normalized.accentColor === normalized.primaryColor) {
    errors.accentColor = "Choose an accent distinct from the primary color.";
  }
  if (
    normalized.timezone.length > 64 ||
    !timezonePattern.test(normalized.timezone)
  ) {
    errors.timezone = "Use a canonical IANA timezone such as Europe/Rome.";
  }
  if (normalized.locale.length > 35 || !localePattern.test(normalized.locale)) {
    errors.locale = "Use a BCP 47 language tag such as it-IT.";
  }
  return errors;
}

export function tenantSettingsUpdateRequest(
  expectedVersion: number,
  draft: TenantSettingsDraft,
): TenantSettingsUpdateRequest {
  const normalized = normalizeTenantSettingsDraft(draft);
  if (
    !Number.isSafeInteger(expectedVersion) ||
    expectedVersion < 1 ||
    expectedVersion >= 2_147_483_647 ||
    Object.keys(tenantSettingsDraftErrors(normalized)).length > 0
  ) {
    throw new TypeError("Tenant settings update input is invalid.");
  }
  return { expectedVersion, ...normalized };
}

export function isTenantSettingsProjection(
  value: unknown,
  tenantId: string,
): value is TenantSettings {
  if (!isExactObject(value, tenantSettingsProjectionKeys)) return false;
  if (
    !isCanonicalUuidV7(tenantId) ||
    value.tenantId !== tenantId ||
    typeof value.version !== "number" ||
    !Number.isSafeInteger(value.version) ||
    value.version < 1 ||
    value.version > 2_147_483_647 ||
    typeof value.updatedAt !== "string" ||
    parseRfc3339Instant(value.updatedAt) === undefined
  ) {
    return false;
  }
  if (
    typeof value.accentColor !== "string" ||
    typeof value.brandMark !== "string" ||
    typeof value.brandName !== "string" ||
    typeof value.locale !== "string" ||
    typeof value.primaryColor !== "string" ||
    typeof value.timezone !== "string"
  ) {
    return false;
  }
  const draft: TenantSettingsDraft = {
    accentColor: value.accentColor,
    brandMark: value.brandMark,
    brandName: value.brandName,
    locale: value.locale,
    primaryColor: value.primaryColor,
    timezone: value.timezone,
  };
  return (
    Object.keys(tenantSettingsDraftErrors(draft)).length === 0 &&
    JSON.stringify(normalizeTenantSettingsDraft(draft)) ===
      JSON.stringify(draft)
  );
}

export function tenantSettingsReasonIsValid(reason: string): boolean {
  return (
    reason.length >= 1 &&
    reason.length <= 500 &&
    /^[\x21-\x2B\x2D-\x7E](?:[\x20-\x2B\x2D-\x7E]*[\x21-\x2B\x2D-\x7E])?$/u.test(
      reason,
    )
  );
}

const tenantSettingsProjectionKeys = [
  "accentColor",
  "brandMark",
  "brandName",
  "locale",
  "primaryColor",
  "tenantId",
  "timezone",
  "updatedAt",
  "version",
] as const;

function isExactObject(
  value: unknown,
  expectedKeys: readonly string[],
): value is Record<string, unknown> {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    return false;
  }
  const keys = Object.keys(value).toSorted();
  const sortedExpectedKeys = expectedKeys.toSorted();
  return (
    keys.length === sortedExpectedKeys.length &&
    keys.every((key, index) => key === sortedExpectedKeys[index])
  );
}
