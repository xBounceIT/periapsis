import type { TenantView, TenantLifecycleAction } from "../lib/phase-two-types";
const forbiddenReasonCodePoint = /[\p{Cc}\p{Cf}]/u;

export class TenantLifecycleClientError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TenantLifecycleClientError";
  }
}

export function tenantLifecycleExpectedVersion(
  tenant: TenantView,
  action: TenantLifecycleAction,
  reason: string,
): number {
  const targetMatches =
    (action === "suspend" && tenant.status === "active") ||
    (action === "reactivate" && tenant.status === "suspended");
  const version = tenant.version;
  if (
    !targetMatches ||
    !isMutableTenantLifecycleVersion(version) ||
    validateTenantLifecycleReason(reason) !== null
  ) {
    throw new TenantLifecycleClientError(
      "The tenant lifecycle confirmation is incomplete or no longer current.",
    );
  }
  return version;
}

export function isMutableTenantLifecycleVersion(
  version: number | undefined,
): version is number {
  return (
    version !== undefined &&
    Number.isSafeInteger(version) &&
    version >= 1 &&
    version <= 2_147_483_646
  );
}

export function tenantLifecycleReasonBytes(reason: string): number {
  return new TextEncoder().encode(reason).byteLength;
}

export function validateTenantLifecycleReason(reason: string): string | null {
  if (reason.trim() === "") return "Enter an administrative reason.";
  if (reason.trim() !== reason)
    return "Remove leading or trailing whitespace from the reason.";
  if (forbiddenReasonCodePoint.test(reason))
    return "Remove control or formatting characters from the reason.";
  if (tenantLifecycleReasonBytes(reason) > 2 * 1024)
    return "Keep the reason within 2048 UTF-8 bytes.";
  return null;
}
