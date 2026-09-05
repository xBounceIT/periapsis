import { hasControlCharacters } from "../lib/text-validation";
import { canonicalizeServiceAccountCredentialNetworks } from "../lib/service-account-networks";
import {
  describePhaseTwoError,
  PhaseTwoApiError,
  type ServiceAccountCredentialSecretView,
  type ServiceAccountCredentialPageView,
  type ServiceAccountCredentialView,
  type ServiceAccountRoleGrantPageView,
  type ServiceAccountRoleGrantView,
  type ServiceAccountView,
  type TenantRolePageView,
  type TenantRoleSummaryView,
  type VersionedView,
} from "../lib/phase-two-types";

export type AccountListState =
  | { kind: "authority_error"; message: string }
  | { kind: "error"; message: string }
  | { kind: "forbidden" }
  | { kind: "inactive" }
  | {
      items: readonly ServiceAccountView[];
      kind: "ready";
      nextCursor?: string;
    }
  | { kind: "loading" };

export interface PairSnapshot<T> {
  pairKey: string;
  state: T;
}

export interface PaginationState {
  error?: string;
  loading: boolean;
}

export interface OneTimeSecretState {
  operation: "issued" | "rotated";
  pairKey: string;
  secret: ServiceAccountCredentialSecretView;
}

export interface ServiceAccountDetailReady {
  account: VersionedView<ServiceAccountView>;
  credentials: ServiceAccountCredentialPageView;
  grants: ServiceAccountRoleGrantPageView;
  kind: "ready";
}

export type ServiceAccountDetailState =
  | { kind: "error"; message: string }
  | { kind: "forbidden" }
  | { kind: "loading" }
  | ServiceAccountDetailReady;

export type MachineRoleState =
  | { kind: "error"; message: string }
  | { kind: "inactive" }
  | { kind: "loading" }
  | {
      items: readonly TenantRoleSummaryView[];
      kind: "ready";
      nextCursor?: string;
    };

const maximumVersion = 2_147_483_647;
const serviceAccountKeyPattern = /^[a-z][a-z0-9_]{2,63}$/;

export const credentialPermission = [
  { permissionKey: "alert.create", scope: "tenant" },
] as const;

export function deriveInitialListState(
  tenantId: string | undefined,
  status: string,
  message: string | undefined,
  canRead: boolean,
): AccountListState {
  if (!tenantId) return { kind: "inactive" };
  if (status === "error") {
    return {
      kind: "authority_error",
      message:
        message ??
        "Live tenant authority is unavailable. Service-account access stays closed.",
    };
  }
  if (status === "forbidden" || (status === "ready" && !canRead)) {
    return { kind: "forbidden" };
  }
  return { kind: "loading" };
}

export function assertAccountTenant(
  accounts: readonly ServiceAccountView[],
  tenantId: string,
): void {
  if (accounts.some((account) => account.tenantId !== tenantId)) {
    throw new Error("The service-account response escaped the active tenant.");
  }
}

export function mergeServiceAccounts(
  current: readonly ServiceAccountView[],
  incoming: readonly ServiceAccountView[],
): readonly ServiceAccountView[] {
  return mergeVersioned(
    current,
    incoming,
    sameServiceAccount,
    "service-account inventory",
  );
}

export function mergeGrants(
  current: readonly ServiceAccountRoleGrantView[],
  incoming: readonly ServiceAccountRoleGrantView[],
): readonly ServiceAccountRoleGrantView[] {
  return mergeVersioned(
    current,
    incoming,
    (left, right) => JSON.stringify(left) === JSON.stringify(right),
    "machine-role grant inventory",
  );
}

export function mergeCredentials(
  current: readonly ServiceAccountCredentialView[],
  incoming: readonly ServiceAccountCredentialView[],
): readonly ServiceAccountCredentialView[] {
  return mergeVersioned(
    current,
    incoming,
    (left, right) => JSON.stringify(left) === JSON.stringify(right),
    "credential inventory",
  );
}

export function mergeRoles(
  current: readonly TenantRoleSummaryView[],
  incoming: readonly TenantRoleSummaryView[],
): readonly TenantRoleSummaryView[] {
  return mergeVersioned(
    current,
    incoming,
    (left, right) => JSON.stringify(left) === JSON.stringify(right),
    "machine-role catalog",
  );
}

function mergeVersioned<T extends { id: string; version: number }>(
  current: readonly T[],
  incoming: readonly T[],
  sameRepresentation: (left: T, right: T) => boolean,
  label: string,
): readonly T[] {
  const merged = new Map<string, T>();
  for (const value of [...current, ...incoming]) {
    if (!validVersion(value.version)) {
      throw new Error(`The ${label} returned an invalid version.`);
    }
    const accepted = merged.get(value.id);
    if (!accepted || value.version > accepted.version) {
      merged.set(value.id, value);
      continue;
    }
    if (value.version < accepted.version) continue;
    if (!sameRepresentation(accepted, value)) {
      throw new Error(
        `The ${label} returned conflicting representations at the same version.`,
      );
    }
  }
  return [...merged.values()];
}

function sameServiceAccount(
  left: ServiceAccountView,
  right: ServiceAccountView,
): boolean {
  return (
    left.id === right.id &&
    left.tenantId === right.tenantId &&
    left.key === right.key &&
    left.displayName === right.displayName &&
    left.description === right.description &&
    left.state === right.state &&
    left.archivedAt === right.archivedAt &&
    left.archivedByMembershipId === right.archivedByMembershipId &&
    left.archiveReason === right.archiveReason &&
    left.version === right.version &&
    left.createdAt === right.createdAt &&
    left.updatedAt === right.updatedAt
  );
}

function validVersion(version: number): boolean {
  return (
    Number.isSafeInteger(version) && version > 0 && version <= maximumVersion
  );
}

export function machineRoleItems(
  page: TenantRolePageView,
): TenantRoleSummaryView[] {
  return page.items.filter(
    (role) => role.principalKind === "service_account" && !role.archived,
  );
}

export function validateAccountForm(
  key: string,
  displayName: string,
  description: string,
): string | null {
  if (!serviceAccountKeyPattern.test(key.trim())) {
    return "Use 3–64 lowercase letters, numbers, or underscores for the key, starting with a letter.";
  }
  const name = displayName.trim();
  if (!name || name.length > 120 || hasControlCharacters(name)) {
    return "Enter a control-character-free display name using 120 characters or fewer.";
  }
  if (description.length > 500 || hasControlCharacters(description)) {
    return "Use a description without control characters and no more than 500 characters.";
  }
  return null;
}

export function validateReason(reason: string): string | null {
  const normalized = reason.trim();
  if (
    !normalized ||
    normalized.length > 500 ||
    hasControlCharacters(normalized)
  ) {
    return "Enter a control-character-free reason using 500 characters or fewer.";
  }
  return null;
}

export function optionalFutureInstant(value: string): string | undefined {
  if (!value) return undefined;
  const parsed = new Date(value);
  if (Number.isNaN(parsed.valueOf()) || parsed.valueOf() <= Date.now()) {
    return undefined;
  }
  return parsed.toISOString();
}

export function credentialInput(
  rawLabel: string,
  rawExpiry: string,
  rawNetworks: string,
):
  | {
      allowedNetworks: string[];
      expiresAt: string;
      label: string;
      ok: true;
    }
  | { message: string; ok: false } {
  const label = rawLabel.trim();
  if (!label || label.length > 120 || hasControlCharacters(label)) {
    return {
      message:
        "Enter a control-character-free credential label using 120 characters or fewer.",
      ok: false,
    };
  }
  const parsedExpiry = new Date(rawExpiry);
  const now = Date.now();
  const maximumExpiry = now + 90 * 24 * 60 * 60 * 1000;
  if (
    Number.isNaN(parsedExpiry.valueOf()) ||
    parsedExpiry.valueOf() <= now ||
    parsedExpiry.valueOf() > maximumExpiry
  ) {
    return {
      message:
        "Choose a credential expiry after now and no more than 90 days away.",
      ok: false,
    };
  }
  const enteredNetworks = rawNetworks
    .split(/\r?\n/u)
    .map((network) => network.trim())
    .filter(Boolean);
  const allowedNetworks =
    canonicalizeServiceAccountCredentialNetworks(enteredNetworks);
  if (!allowedNetworks) {
    return {
      message:
        "Enter up to 32 unique canonical IPv4 or IPv6 CIDRs, one per line.",
      ok: false,
    };
  }
  return {
    allowedNetworks,
    expiresAt: parsedExpiry.toISOString(),
    label,
    ok: true,
  };
}

export function defaultCredentialExpiry(): string {
  return toLocalDateTime(
    new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
  );
}

export function toLocalDateTime(value: string): string {
  const instant = new Date(value);
  if (Number.isNaN(instant.valueOf())) return "";
  const offset = instant.getTimezoneOffset() * 60_000;
  return new Date(instant.valueOf() - offset).toISOString().slice(0, 16);
}

export function formatTimestamp(value: string): string {
  const instant = new Date(value);
  if (Number.isNaN(instant.valueOf())) return "Unavailable";
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(instant);
}

export function capitalize(value: string): string {
  return `${value.slice(0, 1).toUpperCase()}${value.slice(1)}`;
}

export function mutationMessage(error: unknown, fallback: string): string {
  if (error instanceof PhaseTwoApiError) {
    if (error.status === 403) {
      return "Live tenant authority no longer permits this action.";
    }
    if (error.status === 409) {
      return `${describePhaseTwoError(error, fallback)} Reload the current server representation before retrying.`;
    }
    if (error.status === 428) {
      return "The server requires the current strong ETag. Reload the resource before retrying.";
    }
  }
  return describePhaseTwoError(error, fallback);
}

export function isAbortError(error: unknown): boolean {
  return error instanceof DOMException && error.name === "AbortError";
}
