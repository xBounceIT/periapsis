import type {
  TenantLdapAuthProviderBindingCreateInput,
  TenantLdapAuthProviderBindingUpdateInput,
  TenantLdapAuthProviderBindingView,
  TenantLdapMappingCreateInput,
  TenantLdapMappingUpdateInput,
  TenantLdapMappingView,
} from "../lib/phase-two-types";

export interface LdapBindingDraft {
  enabled: boolean;
  loginKey: string;
  profilePriority: string;
}

export interface LdapMappingDraft {
  assignmentEpochId: string;
  caseMode: "insensitive" | "sensitive";
  enabled: boolean;
  matcherType: "exact_cn" | "exact_dn" | "regex";
  matcherValue: string;
  notes: string;
  operatorTeamId: string;
  priority: string;
  reason: string;
  reconciliationMode: "additive" | "authoritative";
  roleIds: string;
  tenantSecurityGroupId: string;
}

const canonicalUuidPattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export function createLdapBindingDraft(): LdapBindingDraft {
  return { enabled: false, loginKey: "", profilePriority: "100" };
}

export function bindingDraftFromView(
  binding: TenantLdapAuthProviderBindingView,
): LdapBindingDraft {
  return {
    enabled: binding.enabled,
    loginKey: binding.loginKey,
    profilePriority: String(binding.profilePriority),
  };
}

export function validateLdapBindingDraft(
  draft: LdapBindingDraft,
): readonly string[] {
  const errors: string[] = [];
  if (!/^[a-z][a-z0-9_-]{2,63}$/.test(draft.loginKey)) {
    errors.push(
      "Login key must be 3–64 lowercase characters and start with a letter.",
    );
  }
  if (!boundedInteger(draft.profilePriority, 0, 1_000_000)) {
    errors.push("Profile priority must be an integer from 0 to 1,000,000.");
  }
  return errors;
}

export function toLdapBindingCreateInput(
  providerId: string,
  draft: LdapBindingDraft,
): TenantLdapAuthProviderBindingCreateInput {
  return {
    enabled: draft.enabled,
    loginKey: draft.loginKey,
    profilePriority: Number(draft.profilePriority),
    providerId,
  };
}

export function toLdapBindingUpdateInput(
  draft: LdapBindingDraft,
): TenantLdapAuthProviderBindingUpdateInput {
  return {
    enabled: draft.enabled,
    loginKey: draft.loginKey,
    profilePriority: Number(draft.profilePriority),
  };
}

export function createLdapMappingDraft(): LdapMappingDraft {
  return {
    assignmentEpochId: "",
    caseMode: "insensitive",
    enabled: false,
    matcherType: "exact_cn",
    matcherValue: "",
    notes: "",
    operatorTeamId: "",
    priority: "100",
    reason: "",
    reconciliationMode: "additive",
    roleIds: "",
    tenantSecurityGroupId: "",
  };
}

export function mappingDraftFromView(
  mapping: TenantLdapMappingView,
): LdapMappingDraft {
  const matcherValue =
    mapping.matcher.type === "exact_dn"
      ? mapping.matcher.dn
      : mapping.matcher.type === "exact_cn"
        ? mapping.matcher.cn
        : mapping.matcher.pattern;
  return {
    assignmentEpochId:
      mapping.target.operatorTeamAssignment?.assignmentEpochId ?? "",
    caseMode: mapping.matcher.caseMode,
    enabled: mapping.enabled,
    matcherType: mapping.matcher.type,
    matcherValue,
    notes: mapping.notes,
    operatorTeamId: mapping.target.operatorTeamAssignment?.operatorTeamId ?? "",
    priority: String(mapping.priority),
    reason: "",
    reconciliationMode: mapping.reconciliationMode,
    roleIds: mapping.target.roleIds.join("\n"),
    tenantSecurityGroupId: mapping.target.tenantSecurityGroupId,
  };
}

export function validateLdapMappingDraft(
  draft: LdapMappingDraft,
): readonly string[] {
  const errors: string[] = [];
  const matcherBytes = new TextEncoder().encode(draft.matcherValue).length;
  if (
    draft.matcherValue.length < 1 ||
    (draft.matcherType === "exact_dn"
      ? draft.matcherValue.length > 2_048 || matcherBytes > 8_192
      : draft.matcherValue.length > 512)
  ) {
    errors.push(
      draft.matcherType === "exact_dn"
        ? "Exact DN must contain 1–2,048 characters and at most 8,192 UTF-8 bytes."
        : "CN or RE2 matcher must contain 1–512 characters.",
    );
  }
  if (
    draft.matcherType !== "regex" &&
    draft.matcherValue.trim() !== draft.matcherValue
  ) {
    errors.push("Exact matcher values cannot start or end with whitespace.");
  }
  if (!boundedInteger(draft.priority, 0, 1_000_000)) {
    errors.push("Mapping priority must be an integer from 0 to 1,000,000.");
  }
  if (!canonicalUuidPattern.test(draft.tenantSecurityGroupId)) {
    errors.push("Choose an exact tenant security-group ID.");
  }
  const roleIds = parseRoleIds(draft.roleIds);
  if (
    roleIds.length < 1 ||
    roleIds.length > 32 ||
    roleIds.some((id) => !canonicalUuidPattern.test(id)) ||
    new Set(roleIds).size !== roleIds.length
  ) {
    errors.push("Provide 1–32 unique canonical tenant role IDs.");
  }
  const hasTeam = draft.operatorTeamId !== "";
  const hasEpoch = draft.assignmentEpochId !== "";
  if (
    hasTeam !== hasEpoch ||
    (hasTeam &&
      (!canonicalUuidPattern.test(draft.operatorTeamId) ||
        !canonicalUuidPattern.test(draft.assignmentEpochId)))
  ) {
    errors.push(
      "Operator team and its exact live assignment epoch must be supplied together.",
    );
  }
  if (draft.notes.length > 2_000) {
    errors.push("Notes cannot exceed 2,000 characters.");
  }
  if (validateLdapMutationReason(draft.reason) !== null) {
    errors.push(validateLdapMutationReason(draft.reason)!);
  }
  return errors;
}

export function toLdapMappingCreateInput(
  bindingId: string,
  draft: LdapMappingDraft,
): TenantLdapMappingCreateInput {
  return {
    bindingId,
    matcher: matcherFromDraft(draft),
    notes: draft.notes,
    priority: Number(draft.priority),
    reason: draft.reason,
    reconciliationMode: draft.reconciliationMode,
    target: targetFromDraft(draft),
  };
}

export function toLdapMappingUpdateInput(
  draft: LdapMappingDraft,
): TenantLdapMappingUpdateInput {
  return {
    enabled: draft.enabled,
    matcher: matcherFromDraft(draft),
    notes: draft.notes,
    priority: Number(draft.priority),
    reason: draft.reason,
    reconciliationMode: draft.reconciliationMode,
    target: targetFromDraft(draft),
  };
}

export function validateLdapMutationReason(reason: string): string | null {
  if (reason.length < 1 || reason.length > 500) {
    return "Reason must contain 1–500 characters.";
  }
  if (/\p{Cc}/u.test(reason)) {
    return "Reason cannot contain control characters.";
  }
  return null;
}

function matcherFromDraft(
  draft: LdapMappingDraft,
): TenantLdapMappingCreateInput["matcher"] {
  const common = { caseMode: draft.caseMode };
  if (draft.matcherType === "exact_dn") {
    return { ...common, dn: draft.matcherValue, type: "exact_dn" };
  }
  if (draft.matcherType === "exact_cn") {
    return { ...common, cn: draft.matcherValue, type: "exact_cn" };
  }
  return { ...common, pattern: draft.matcherValue, type: "regex" };
}

function targetFromDraft(
  draft: LdapMappingDraft,
): TenantLdapMappingCreateInput["target"] {
  return {
    operatorTeamAssignment:
      draft.operatorTeamId && draft.assignmentEpochId
        ? {
            assignmentEpochId: draft.assignmentEpochId,
            operatorTeamId: draft.operatorTeamId,
          }
        : null,
    roleIds: parseRoleIds(draft.roleIds),
    tenantSecurityGroupId: draft.tenantSecurityGroupId,
  };
}

function parseRoleIds(value: string): string[] {
  return value
    .split(/[\s,]+/u)
    .map((item) => item.trim())
    .filter(Boolean);
}

function boundedInteger(
  value: string,
  minimum: number,
  maximum: number,
): boolean {
  if (!/^(0|[1-9]\d*)$/.test(value)) return false;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed >= minimum && parsed <= maximum;
}
