import type { DfirAlertWorkspace } from "@periapsis/contracts";

export const alertDfirTenantId = "0198c97d-cf4f-7000-8000-000000000001";
export const alertDfirAlertId = "0198c97d-cf4f-7000-8000-000000000020";
export const alertDfirIndicatorId = "0198c97d-cf4f-7000-8000-000000000003";
export const alertDfirAssetId = "0198c97d-cf4f-7000-8000-000000000004";
export const alertDfirTimelineId = "0198c97d-cf4f-7000-8000-000000000006";
export const alertDfirAttachmentId = "0198c97d-cf4f-7000-8000-000000000008";
export const alertDfirEvidenceId = "0198c97d-cf4f-7000-8000-000000000021";
export const alertDfirTaskId = "0198c97d-cf4f-7000-8000-000000000025";
export const alertDfirRelationshipId = "0198c97d-cf4f-7000-8000-000000000027";
const storageId = "0198c97d-cf4f-7000-8000-000000000010";
export const alertDfirActorId = "0198c97d-cf4f-7000-8000-000000000011";

export function alertDfirWorkspaceFixture(
  overrides: Partial<DfirAlertWorkspace> = {},
): DfirAlertWorkspace {
  return {
    sharedResources: [
      ...(overrides.indicators ?? [{ id: alertDfirIndicatorId }]).map(
        ({ id }) => ({
          resourceKind: "ioc" as const,
          resourceId: id,
          roots: [{ kind: "alert" as const, id: alertDfirAlertId }],
        }),
      ),
      ...(overrides.assets ?? [{ id: alertDfirAssetId }]).map(({ id }) => ({
        resourceKind: "asset" as const,
        resourceId: id,
        roots: [{ kind: "alert" as const, id: alertDfirAlertId }],
      })),
    ],
    alertId: alertDfirAlertId,
    assets: [
      {
        alertId: alertDfirAlertId,
        asset: {
          assetType: "endpoint",
          businessUnit: "Security",
          criticality: "high",
          environment: "production",
          externalId: "asset-42",
          firstSeen: "2026-08-30T08:00:00.000Z",
          fqdn: "host.example.test",
          hostname: "host",
          ipAddresses: ["192.0.2.4"],
          lastSeen: "2026-08-30T09:00:00.000Z",
          macAddresses: [],
          operatingSystem: "Linux",
          owner: "SOC",
          tags: ["critical"],
        },
        id: alertDfirAssetId,
        tenantId: alertDfirTenantId,
        version: 2,
      },
    ],
    evidence: [],
    attachments: [
      {
        id: alertDfirAttachmentId,
        originalFilename: "memory.raw",
        scanState: "available",
        storageObjectId: storageId,
        subject: { id: alertDfirAlertId, kind: "alert" },
        tenantId: alertDfirTenantId,
        uploadedAt: "2026-08-30T09:00:00.000Z",
        uploadedBy: alertDfirActorId,
        visibility: "private",
      },
    ],
    indicators: [
      {
        alertId: alertDfirAlertId,
        id: alertDfirIndicatorId,
        indicator: {
          confidence: 80,
          description: "Command and control domain",
          firstSeen: "2026-08-30T08:00:00.000Z",
          lastSeen: "2026-08-30T09:00:00.000Z",
          malicious: "confirmed",
          source: "EDR",
          tags: ["c2"],
          tlp: "amber",
          type: "domain",
          value: "bad.example",
        },
        tenantId: alertDfirTenantId,
        version: 4,
      },
    ],
    relationships: [],
    tasks: [],
    tenantId: alertDfirTenantId,
    timeline: [
      {
        alertId: alertDfirAlertId,
        event: {
          assetIds: [alertDfirAssetId],
          category: "process_start",
          description: "Suspicious process launched",
          eventTime: "2026-08-30T08:15:00.000Z",
          evidenceIds: [],
          iocIds: [alertDfirIndicatorId],
          originalTimezone: "UTC",
          precision: "second",
          source: "EDR",
          tags: [],
          title: "PowerShell launch",
        },
        id: alertDfirTimelineId,
        ingestedAt: "2026-08-30T09:00:00.000Z",
        tenantId: alertDfirTenantId,
        version: 1,
      },
    ],
    ...overrides,
  };
}

export function alertDfirExtendedWorkspaceFixture(): DfirAlertWorkspace {
  const workspace = alertDfirWorkspaceFixture();
  return {
    ...workspace,
    evidence: [
      {
        alertId: alertDfirAlertId,
        classification: "restricted",
        collectedAt: "2026-08-30T09:05:00.000Z",
        collectedBy: alertDfirActorId,
        contentSha256: "a".repeat(64),
        custody: [
          {
            action: "collected",
            actorId: alertDfirActorId,
            eventHash: "b".repeat(64),
            id: "0198c97d-cf4f-7000-8000-000000000023",
            occurredAt: "2026-08-30T09:05:00.000Z",
            previousHash: "c".repeat(64),
            reason: "Initial protected collection",
            sequence: 1,
            stateValue: "available",
          },
          {
            action: "accessed",
            actorId: alertDfirActorId,
            eventHash: "d".repeat(64),
            id: "0198c97d-cf4f-7000-8000-000000000093",
            occurredAt: "2026-08-30T09:06:00.000Z",
            previousHash: "b".repeat(64),
            reason: "Integrity review",
            sequence: 2,
            stateValue: "",
          },
          {
            action: "accessed",
            actorId: alertDfirActorId,
            eventHash: "e".repeat(64),
            id: "0198c97d-cf4f-7000-8000-000000000094",
            occurredAt: "2026-08-30T09:07:00.000Z",
            previousHash: "d".repeat(64),
            reason: "Investigation review",
            sequence: 3,
            stateValue: "",
          },
        ],
        description: "Verified volatile memory image",
        destroyed: false,
        detectedMime: "application/octet-stream",
        evidenceType: "memory_image",
        id: alertDfirEvidenceId,
        legalHold: true,
        retentionUntil: "2027-08-30T09:05:00.000Z",
        scanState: "available",
        sealed: true,
        sizeBytes: 4_096,
        source: "EDR",
        storageObjectId: "0198c97d-cf4f-7000-8000-000000000022",
        tenantId: alertDfirTenantId,
        title: "Memory image",
        version: 3,
      },
    ],
    relationships: [
      {
        active: true,
        alertId: alertDfirAlertId,
        createdAt: "2026-08-30T09:10:00.000Z",
        createdBy: alertDfirActorId,
        id: alertDfirRelationshipId,
        relationshipType: "contains",
        retractions: [],
        source: { id: alertDfirAlertId, kind: "alert" },
        target: { id: alertDfirEvidenceId, kind: "evidence" },
        tenantId: alertDfirTenantId,
        version: 1,
      },
    ],
    tasks: [
      {
        alertId: alertDfirAlertId,
        checklist: [
          {
            completed: false,
            id: "0198c97d-cf4f-7000-8000-000000000026",
            title: "Acquire triage bundle",
          },
        ],
        commentIds: [],
        createdAt: "2026-08-30T09:06:00.000Z",
        description: "Preserve volatile evidence",
        id: alertDfirTaskId,
        priority: "urgent",
        status: "todo",
        tenantId: alertDfirTenantId,
        title: "Contain endpoint",
        updatedAt: "2026-08-30T09:06:00.000Z",
        version: 2,
      },
    ],
    timeline: workspace.timeline.map((event) => ({
      ...event,
      event: { ...event.event, evidenceIds: [alertDfirEvidenceId] },
    })),
  };
}

export function boundAlertDfirWorkspaceFixture(
  tenantId: string,
  alertId: string,
): DfirAlertWorkspace {
  const workspace = alertDfirWorkspaceFixture();
  return {
    ...workspace,
    alertId,
    assets: workspace.assets.map((item) => ({ ...item, alertId, tenantId })),
    evidence: workspace.evidence.map((item) => ({
      ...item,
      alertId,
      tenantId,
    })),
    attachments: workspace.attachments.map((item) => ({
      ...item,
      subject: { id: alertId, kind: "alert" },
      tenantId,
    })),
    indicators: workspace.indicators.map((item) => ({
      ...item,
      alertId,
      tenantId,
    })),
    relationships: workspace.relationships.map((item) => ({
      ...item,
      alertId,
      tenantId,
    })),
    sharedResources: workspace.sharedResources.map((item) => ({
      ...item,
      roots: [{ kind: "alert", id: alertId }],
    })),
    tasks: workspace.tasks.map((item) => ({ ...item, alertId, tenantId })),
    tenantId,
    timeline: workspace.timeline.map((item) => ({
      ...item,
      alertId,
      tenantId,
    })),
  };
}
