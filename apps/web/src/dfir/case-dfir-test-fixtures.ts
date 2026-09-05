import type { DfirWorkspace } from "@periapsis/contracts";

export const dfirTenantId = "0198c97d-cf4f-7000-8000-000000000001";
export const dfirCaseId = "0198c97d-cf4f-7000-8000-000000000002";
export const dfirIndicatorId = "0198c97d-cf4f-7000-8000-000000000003";
export const dfirAssetId = "0198c97d-cf4f-7000-8000-000000000004";
export const dfirEvidenceId = "0198c97d-cf4f-7000-8000-000000000005";
export const dfirTimelineId = "0198c97d-cf4f-7000-8000-000000000006";
export const dfirTaskId = "0198c97d-cf4f-7000-8000-000000000007";
export const dfirAttachmentId = "0198c97d-cf4f-7000-8000-000000000008";
export const dfirRelationshipId = "0198c97d-cf4f-7000-8000-000000000009";
const storageId = "0198c97d-cf4f-7000-8000-000000000010";
const actorId = "0198c97d-cf4f-7000-8000-000000000011";
const custodyId = "0198c97d-cf4f-7000-8000-000000000012";

export function dfirWorkspaceFixture(
  overrides: Partial<DfirWorkspace> = {},
): DfirWorkspace {
  return {
    sharedResources: [
      ...(overrides.indicators ?? [{ id: dfirIndicatorId }]).map(({ id }) => ({
        resourceKind: "ioc" as const,
        resourceId: id,
        roots: [{ kind: "case" as const, id: dfirCaseId }],
      })),
      ...(overrides.assets ?? [{ id: dfirAssetId }]).map(({ id }) => ({
        resourceKind: "asset" as const,
        resourceId: id,
        roots: [{ kind: "case" as const, id: dfirCaseId }],
      })),
    ],
    assets: [
      {
        asset: {
          assetType: "endpoint",
          businessUnit: "Security",
          criticality: "high",
          environment: "production",
          externalId: "asset-42",
          firstSeen: "2026-08-30T08:00:00Z",
          fqdn: "host.example.test",
          hostname: "host",
          ipAddresses: ["192.0.2.4"],
          lastSeen: "2026-08-30T09:00:00Z",
          macAddresses: [],
          operatingSystem: "Linux",
          owner: "SOC",
          tags: ["critical"],
        },
        caseId: dfirCaseId,
        id: dfirAssetId,
        tenantId: dfirTenantId,
        version: 2,
      },
    ],
    attachments: [
      {
        id: dfirAttachmentId,
        originalFilename: "memory.raw",
        scanState: "available",
        storageObjectId: storageId,
        subject: { id: dfirCaseId, kind: "case" },
        tenantId: dfirTenantId,
        uploadedAt: "2026-08-30T09:00:00Z",
        uploadedBy: actorId,
        visibility: "private",
      },
    ],
    caseId: dfirCaseId,
    evidence: [
      {
        caseId: dfirCaseId,
        classification: "restricted",
        collectedAt: "2026-08-30T09:05:00Z",
        collectedBy: actorId,
        contentSha256: "a".repeat(64),
        custody: [
          {
            action: "collected",
            actorId,
            eventHash: "b".repeat(64),
            id: custodyId,
            occurredAt: "2026-08-30T09:05:00Z",
            previousHash: "c".repeat(64),
            reason: "Initial collection",
            sequence: 1,
            stateValue: "available",
          },
          {
            action: "accessed",
            actorId,
            eventHash: "d".repeat(64),
            id: "0198c97d-cf4f-7000-8000-000000000093",
            occurredAt: "2026-08-30T09:06:00Z",
            previousHash: "b".repeat(64),
            reason: "Integrity review",
            sequence: 2,
            stateValue: "",
          },
          {
            action: "accessed",
            actorId,
            eventHash: "e".repeat(64),
            id: "0198c97d-cf4f-7000-8000-000000000094",
            occurredAt: "2026-08-30T09:07:00Z",
            previousHash: "d".repeat(64),
            reason: "Investigation review",
            sequence: 3,
            stateValue: "",
          },
        ],
        description: "Volatile memory acquisition",
        destroyed: false,
        detectedMime: "application/octet-stream",
        evidenceType: "memory_image",
        id: dfirEvidenceId,
        legalHold: true,
        scanState: "available",
        sealed: false,
        sizeBytes: 2_048,
        source: "EDR",
        storageObjectId: storageId,
        tenantId: dfirTenantId,
        title: "Memory image",
        version: 3,
      },
    ],
    indicators: [
      {
        caseId: dfirCaseId,
        id: dfirIndicatorId,
        indicator: {
          confidence: 80,
          description: "Command and control domain",
          firstSeen: "2026-08-30T08:00:00Z",
          lastSeen: "2026-08-30T09:00:00Z",
          malicious: "confirmed",
          source: "EDR",
          tags: ["c2"],
          tlp: "amber",
          type: "domain",
          value: "bad.example",
        },
        tenantId: dfirTenantId,
        version: 4,
      },
    ],
    relationships: [
      {
        active: true,
        createdAt: "2026-08-30T09:10:00Z",
        createdBy: actorId,
        id: dfirRelationshipId,
        relationshipType: "observed_on",
        retractions: [],
        source: { id: dfirCaseId, kind: "case" },
        target: { id: dfirAssetId, kind: "asset" },
        tenantId: dfirTenantId,
        version: 1,
      },
    ],
    tasks: [
      {
        caseId: dfirCaseId,
        checklist: [],
        commentIds: [],
        createdAt: "2026-08-30T09:00:00Z",
        description: "Isolate and acquire the endpoint",
        id: dfirTaskId,
        priority: "high",
        status: "todo",
        tenantId: dfirTenantId,
        title: "Contain endpoint",
        updatedAt: "2026-08-30T09:00:00Z",
        version: 1,
      },
    ],
    tenantId: dfirTenantId,
    timeline: [
      {
        caseId: dfirCaseId,
        event: {
          assetIds: [dfirAssetId],
          category: "process_start",
          description: "Suspicious process launched",
          eventTime: "2026-08-30T08:15:00Z",
          evidenceIds: [],
          iocIds: [dfirIndicatorId],
          originalTimezone: "UTC",
          precision: "second",
          source: "EDR",
          tags: [],
          title: "PowerShell launch",
        },
        id: dfirTimelineId,
        ingestedAt: "2026-08-30T09:00:00Z",
        tenantId: dfirTenantId,
        version: 1,
      },
    ],
    ...overrides,
  };
}
