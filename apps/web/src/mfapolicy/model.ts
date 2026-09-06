import type {
  MfaPolicyDocument,
  MfaPolicyMutationResult,
  MfaPolicyPage,
  MfaPolicyRequirement,
  MfaPolicySimulationContext,
  MfaPolicySimulationResult,
} from "@periapsis/contracts";

import { generateUuidV7 } from "../lib/uuid-v7";

export const platformMfaPolicyReadPermission =
  "platform.identity_policy.read" as const;
export const platformMfaPolicyManagePermission =
  "platform.identity_policy.manage" as const;
export const tenantMfaPolicyReadPermission = "identity_policy.read" as const;
export const tenantMfaPolicyManagePermission =
  "identity_policy.manage" as const;

export const platformMfaPolicyRouteDescriptor = {
  label: "Platform MFA policy",
  path: "/platform/mfa-policies",
  permissions: [platformMfaPolicyReadPermission],
} as const;

export const tenantMfaPolicyRouteDescriptor = {
  label: "MFA policies",
  path: "/tenant/mfa-policies",
  permissions: [tenantMfaPolicyReadPermission],
} as const;

export type MfaPolicyBoundary =
  { kind: "platform" } | { kind: "tenant"; tenantId: string };

export type PlatformMfaPolicyTargetInput = { scope: "platform_floor" };
export type TenantMfaPolicyTargetInput =
  | { scope: "tenant_baseline" }
  | { roleId: string; scope: "role" }
  | { scope: "security_group"; securityGroupId: string }
  | { action: string; scope: "action" };
export type MfaPolicyTargetInput =
  PlatformMfaPolicyTargetInput | TenantMfaPolicyTargetInput;

export interface MfaPolicyListInput {
  after?: { id: string; revision: number };
  includeRetired?: boolean;
  signal?: AbortSignal;
}

export interface MfaPolicySimulationInput {
  context?: MfaPolicySimulationContext;
  expectedPolicyId?: string;
  expectedRevision: number;
  operation: "publish" | "retire";
  requirement?: MfaPolicyRequirement;
  target: MfaPolicyTargetInput;
}

export interface MfaPolicyPublishInput {
  expectedRevision: 0;
  requirement: MfaPolicyRequirement;
  target: MfaPolicyTargetInput;
}

export interface MfaPolicyReplaceInput {
  expectedRevision: number;
  requirement: MfaPolicyRequirement;
  target: MfaPolicyTargetInput;
}

export interface MfaPolicyRetireInput {
  expectedRevision: number;
  target: MfaPolicyTargetInput;
}

export interface VersionedMfaPolicyDocument {
  etag: string;
  value: MfaPolicyDocument;
}

export interface VersionedMfaPolicyMutation {
  etag: string;
  value: MfaPolicyMutationResult;
}

export interface MfaPolicyApi {
  get(
    boundary: MfaPolicyBoundary,
    policyId: string,
    revision: number,
    signal?: AbortSignal,
  ): Promise<VersionedMfaPolicyDocument>;
  list(
    boundary: MfaPolicyBoundary,
    input?: MfaPolicyListInput,
  ): Promise<MfaPolicyPage>;
  publish(
    boundary: MfaPolicyBoundary,
    csrfToken: string,
    commandId: string,
    reason: string,
    input: MfaPolicyPublishInput,
    signal?: AbortSignal,
  ): Promise<VersionedMfaPolicyMutation>;
  replace(
    boundary: MfaPolicyBoundary,
    csrfToken: string,
    commandId: string,
    reason: string,
    policyId: string,
    etag: string,
    input: MfaPolicyReplaceInput,
    signal?: AbortSignal,
  ): Promise<VersionedMfaPolicyMutation>;
  retire(
    boundary: MfaPolicyBoundary,
    csrfToken: string,
    commandId: string,
    reason: string,
    policyId: string,
    etag: string,
    input: MfaPolicyRetireInput,
    signal?: AbortSignal,
  ): Promise<VersionedMfaPolicyMutation>;
  simulate(
    boundary: MfaPolicyBoundary,
    csrfToken: string,
    input: MfaPolicySimulationInput,
    signal?: AbortSignal,
  ): Promise<MfaPolicySimulationResult>;
}

interface CommandBinding {
  commandId: string;
  fingerprint: string;
}

export interface MfaPolicyCommandReference {
  current: CommandBinding | null;
}

export function bindMfaPolicyCommand(
  reference: MfaPolicyCommandReference,
  boundary: MfaPolicyBoundary,
  operation: "publish" | "retire",
  reason: string,
  input: MfaPolicyPublishInput | MfaPolicyReplaceInput | MfaPolicyRetireInput,
): string {
  const fingerprint = canonicalJson({ boundary, input, operation, reason });
  if (reference.current?.fingerprint !== fingerprint) {
    reference.current = { commandId: generateUuidV7(), fingerprint };
  }
  return reference.current.commandId;
}

export function clearMfaPolicyCommand(
  reference: MfaPolicyCommandReference,
): void {
  reference.current = null;
}

export function isCanonicalUuidV7(value: string): boolean {
  return uuidV7Pattern.test(value);
}

export function isMfaPolicyAuditReason(value: string): boolean {
  if (value.length < 1 || value.length > 2048 || value.trim() !== value) {
    return false;
  }
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code < 0x20 || code > 0x7e || code === 0x2c) return false;
  }
  return true;
}

export function isMfaPolicyInstant(value: string): boolean {
  if (!mfaPolicyInstantPattern.test(value)) return false;
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp) || Number(value.slice(0, 4)) < 1970)
    return false;
  const canonical = new Date(timestamp).toISOString();
  return (
    value === canonical ||
    (canonical.endsWith(".000Z") && value === canonical.replace(".000Z", "Z"))
  );
}

export function normalizeMfaPolicyContext(
  roleIds: readonly string[],
  securityGroupIds: readonly string[],
  action: string,
): MfaPolicySimulationContext {
  const normalizedAction = action.trim();
  if (!validAudience(normalizedAction)) {
    throw new TypeError(
      "Enter an exact non-empty action (up to 256 characters).",
    );
  }
  return {
    action: normalizedAction,
    roleIds: normalizeIds(roleIds, "role"),
    securityGroupIds: normalizeIds(securityGroupIds, "security-group"),
  };
}

// oxlint-disable-next-line typescript/consistent-return -- The target union is exhaustively returned by its discriminator.
export function mfaPolicyTargetApplies(
  target: MfaPolicyTargetInput,
  context: MfaPolicySimulationContext,
): boolean {
  switch (target.scope) {
    case "tenant_baseline":
      return true;
    case "role":
      return context.roleIds.includes(target.roleId);
    case "security_group":
      return context.securityGroupIds.includes(target.securityGroupId);
    case "action":
      return context.action === target.action;
    case "platform_floor":
      return false;
  }
}

export function mfaPolicyDraftFingerprint(value: unknown): string {
  return canonicalJson(value);
}

function normalizeIds(values: readonly string[], label: string): string[] {
  if (values.length > 512) {
    throw new TypeError(`At most 512 ${label} IDs are allowed.`);
  }
  const normalized: string[] = [];
  for (const value of values) {
    const trimmed = value.trim();
    if (trimmed) normalized.push(trimmed);
  }
  if (
    normalized.some((value) => !isCanonicalUuidV7(value)) ||
    new Set(normalized).size !== normalized.length
  ) {
    throw new TypeError(`${label} IDs must be unique canonical UUIDv7 values.`);
  }
  return normalized.toSorted();
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    const serialized = JSON.stringify(value);
    if (serialized === undefined) {
      throw new TypeError("MFA policy commands must be JSON serializable.");
    }
    return serialized;
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  }
  if (Object.getPrototypeOf(value) !== Object.prototype) {
    throw new TypeError("MFA policy commands must use plain JSON objects.");
  }
  return `{${Object.entries(value)
    .filter(([, item]) => item !== undefined)
    .toSorted(([left], [right]) => left.localeCompare(right))
    .map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`)
    .join(",")}}`;
}

function validAudience(value: string): boolean {
  if (value.length < 1 || value.length > 256 || value.trim() !== value) {
    return false;
  }
  return !/[\p{Cc}\p{Cf}]/u.test(value);
}

const uuidV7Pattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const mfaPolicyInstantPattern =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:[0-5]\d(?:\.\d{3})?Z$/u;
