import type { AuditChainVerification, AuditEvent } from "@periapsis/contracts";

import type { AuditReaderApi } from "./audit-api";

export const auditTenantId = "01991c20-7d5f-7000-8000-000000000001";
export const auditActorUserId = "01991c20-7d5f-7000-8000-000000000002";

export const tenantAuditEventFixture: AuditEvent = {
  id: "01991c20-7d5f-7000-8000-000000000003",
  tenantId: auditTenantId,
  sequence: 10,
  occurredAt: "2026-08-25T10:00:00Z",
  actorType: "user",
  actorUserId: auditActorUserId,
  action: "case.transition",
  resourceType: "case",
  resourceId: "01991c20-7d5f-7000-8000-000000000004",
  requestId: "01991c20-7d5f-7000-8000-000000000005",
  correlationId: "01991c20-7d5f-7000-8000-000000000006",
  ipAddress: "192.0.2.18",
  userAgent: "Periapsis test client",
  authenticationMethod: "password+mfa",
  outcome: "success",
  reason: "Approved containment transition",
  before: { status: "triage" },
  after: { status: "contained" },
  metadata: {
    passwordConfigured: true,
    workflow: { version: 3 },
  },
  previousHash: "a".repeat(64),
  eventHash: "b".repeat(64),
};

export const platformAuditEventFixture: AuditEvent = {
  ...tenantAuditEventFixture,
  id: "01991c20-7d5f-7000-8000-000000000007",
  sequence: 21,
  action: "platform.operator_team.updated",
  resourceType: "operator_team",
  resourceId: "01991c20-7d5f-7000-8000-000000000008",
};
delete platformAuditEventFixture.tenantId;

export const auditVerificationFixture: AuditChainVerification = {
  eventCount: 21,
  lastSequence: 21,
  retainedThroughSequence: 0,
  headValid: true,
  valid: true,
  verifiedAt: "2026-08-25T10:01:00Z",
};

export function createAuditApiMock(
  overrides: Partial<AuditReaderApi> = {},
): AuditReaderApi {
  return {
    listTenant: async () => ({ items: [tenantAuditEventFixture] }),
    listPlatform: async () => ({ items: [platformAuditEventFixture] }),
    verifyTenant: async () => auditVerificationFixture,
    verifyPlatform: async () => auditVerificationFixture,
    ...overrides,
  };
}
