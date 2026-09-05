import { describe, expect, it } from "vitest";

import type { TenantLdapMappingView } from "../lib/phase-two-types";
import {
  createLdapBindingDraft,
  createLdapMappingDraft,
  mappingDraftFromView,
  toLdapBindingCreateInput,
  toLdapMappingCreateInput,
  toLdapMappingUpdateInput,
  validateLdapBindingDraft,
  validateLdapMappingDraft,
  validateLdapMutationReason,
} from "./ldap-administration-model";

const providerId = "0198c97d-cf4f-7000-8000-000000000088";
const bindingId = "0198c97d-cf4f-7000-8000-000000000089";
const groupId = "0198c97d-cf4f-7000-8000-000000000090";
const roleId = "0198c97d-cf4f-7000-8000-000000000091";
const teamId = "0198c97d-cf4f-7000-8000-000000000092";
const epochId = "0198c97d-cf4f-7000-8000-000000000093";

describe("LDAP administration drafts", () => {
  it("freezes lowercase binding keys and explicit lifecycle input", () => {
    const draft = createLdapBindingDraft();
    draft.loginKey = "employees_eu";
    draft.profilePriority = "250";
    draft.enabled = true;

    expect(validateLdapBindingDraft(draft)).toEqual([]);
    expect(toLdapBindingCreateInput(providerId, draft)).toEqual({
      enabled: true,
      loginKey: "employees_eu",
      profilePriority: 250,
      providerId,
    });

    draft.loginKey = "Employees";
    expect(validateLdapBindingDraft(draft)).toContain(
      "Login key must be 3–64 lowercase characters and start with a letter.",
    );
  });

  it("builds exactly one typed matcher and an exact team assignment epoch", () => {
    const draft = createLdapMappingDraft();
    Object.assign(draft, {
      assignmentEpochId: epochId,
      caseMode: "sensitive" as const,
      matcherType: "exact_dn" as const,
      matcherValue: "CN=IR,OU=Groups,DC=example,DC=invalid",
      notes: "Tenant incident response authority",
      operatorTeamId: teamId,
      priority: "9",
      reason: "Create the reviewed incident response mapping.",
      reconciliationMode: "authoritative" as const,
      roleIds: `${roleId}\n0198c97d-cf4f-7000-8000-000000000094`,
      tenantSecurityGroupId: groupId,
    });

    expect(validateLdapMappingDraft(draft)).toEqual([]);
    const input = toLdapMappingCreateInput(bindingId, draft);
    expect(input).toEqual({
      bindingId,
      matcher: {
        caseMode: "sensitive",
        dn: "CN=IR,OU=Groups,DC=example,DC=invalid",
        type: "exact_dn",
      },
      notes: "Tenant incident response authority",
      priority: 9,
      reason: "Create the reviewed incident response mapping.",
      reconciliationMode: "authoritative",
      target: {
        operatorTeamAssignment: {
          assignmentEpochId: epochId,
          operatorTeamId: teamId,
        },
        roleIds: [roleId, "0198c97d-cf4f-7000-8000-000000000094"],
        tenantSecurityGroupId: groupId,
      },
    });
    expect(input).not.toHaveProperty("enabled");
  });

  it("rejects half-populated team epochs, duplicate roles and missing reasons", () => {
    const draft = createLdapMappingDraft();
    Object.assign(draft, {
      matcherValue: "responders",
      operatorTeamId: teamId,
      roleIds: `${roleId},${roleId}`,
      tenantSecurityGroupId: groupId,
    });

    expect(validateLdapMappingDraft(draft)).toEqual(
      expect.arrayContaining([
        "Provide 1–32 unique canonical tenant role IDs.",
        "Operator team and its exact live assignment epoch must be supplied together.",
        "Reason must contain 1–500 characters.",
      ]),
    );
    expect(validateLdapMutationReason("bad\nreason")).toBe(
      "Reason cannot contain control characters.",
    );
  });

  it("preserves enabled state only on ETag-protected mapping replacement", () => {
    const draft = mappingDraftFromView(mappingFixture());
    draft.reason = "Review and preserve the live mapping.";
    expect(toLdapMappingUpdateInput(draft)).toMatchObject({
      enabled: true,
      matcher: { cn: "responders", type: "exact_cn" },
      target: { operatorTeamAssignment: null, roleIds: [roleId] },
    });
  });
});

function mappingFixture(): TenantLdapMappingView {
  return {
    archivedAt: null,
    bindingId,
    createdAt: "2026-08-25T09:00:00Z",
    currentSourceEpoch: {
      activatedAt: "2026-08-25T09:01:00Z",
      id: "0198c97d-cf4f-7000-8000-000000000095",
      reconciliationMode: "additive",
      sequence: 1,
    },
    enabled: true,
    id: "0198c97d-cf4f-7000-8000-000000000096",
    lastMatchedAt: null,
    matcher: {
      caseMode: "insensitive",
      cn: "responders",
      type: "exact_cn",
    },
    notes: "",
    priority: 100,
    reconciliationMode: "additive",
    target: {
      operatorTeamAssignment: null,
      roleIds: [roleId],
      tenantSecurityGroupId: groupId,
    },
    tenantId: "0198c97d-cf4f-7000-8000-000000000010",
    updatedAt: "2026-08-25T09:01:00Z",
    version: 2,
  };
}
