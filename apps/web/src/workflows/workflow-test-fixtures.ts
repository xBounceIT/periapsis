import type {
  ManagedWorkflow,
  WorkflowSimulationResult,
  WorkflowVersion,
} from "./model";
import type {
  VersionedWorkflow,
  WorkflowAdministrationApi,
} from "./workflow-api";

export const workflowTenantId = "01991c20-7d5f-7000-8000-000000000201";
export const alertWorkflowId = "01991c20-7d5f-7000-8000-000000000202";

export const alertWorkflowFixture: ManagedWorkflow = {
  id: alertWorkflowId,
  tenantId: workflowTenantId,
  kind: "alert",
  key: "soc_alert",
  displayName: "SOC alert response",
  description: "Governed alert triage and closure.",
  isDefault: true,
  status: "active",
  revision: 1,
  currentVersion: 1,
  current: {
    id: alertWorkflowId,
    kind: "alert",
    version: 1,
    initialState: "new",
    states: [
      {
        key: "closed",
        initial: false,
        terminal: true,
        visibility: "customer",
        actions: [],
      },
      {
        key: "new",
        initial: true,
        terminal: false,
        visibility: "customer",
        actions: [
          {
            action: "create",
            effects: ["activity", "audit", "sla", "notification"],
          },
          { action: "claim", effects: ["activity", "audit"] },
        ],
      },
    ],
    transitions: [
      {
        key: "close",
        from: "new",
        to: "closed",
        requiredComment: true,
        reopen: false,
        requiredRoles: [],
        requiredPermissions: ["alert.update"],
        requiredCustomFields: ["resolution"],
        condition: {
          kind: "predicate",
          field: "severity",
          operator: "in",
          values: [
            { type: "text", value: "high" },
            { type: "text", value: "medium" },
          ],
        },
        effects: ["activity", "audit", "sla", "notification"],
      },
    ],
  },
  createdAt: "2026-08-26T08:00:00Z",
  updatedAt: "2026-08-26T08:00:00Z",
};

export const alertWorkflowVersionFixture: WorkflowVersion = {
  tenantId: workflowTenantId,
  workflowId: alertWorkflowId,
  definition: alertWorkflowFixture.current,
  publishedByMembershipId: "01991c20-7d5f-7000-8000-000000000203",
  publisherDisplayName: "Ada Analyst",
  publishedAt: "2026-08-26T08:00:00Z",
};

export const workflowSimulationFixture: WorkflowSimulationResult = {
  workflowId: alertWorkflowId,
  kind: "alert",
  version: 1,
  explanatory: true,
  transitions: [
    {
      key: "close",
      from: "new",
      to: "closed",
      reopen: false,
      eligible: false,
      gates: {
        commentSatisfied: false,
        roleSatisfied: true,
        permissionsSatisfied: true,
        customFieldsSatisfied: false,
        conditionSatisfied: true,
      },
      missingRoles: [],
      missingPermissions: [],
      missingCustomFields: ["resolution"],
      effects: ["activity", "audit", "sla", "notification"],
    },
  ],
};

export function versionedWorkflow(
  value: ManagedWorkflow = alertWorkflowFixture,
): VersionedWorkflow {
  return {
    etag: `"v${value.revision}-_VFDEoAgKP5tR_AyfYsxkZwrjrziGnhwdGR6LyK4ovU"`,
    replayed: false,
    value,
  };
}

export function createWorkflowApiMock(
  overrides: Partial<WorkflowAdministrationApi> = {},
): WorkflowAdministrationApi {
  const api: WorkflowAdministrationApi = {
    list: async () => ({ items: [alertWorkflowFixture] }),
    get: async () => versionedWorkflow(),
    create: async ({ body }) =>
      versionedWorkflow({
        ...alertWorkflowFixture,
        id: alertWorkflowId,
        kind: body.kind,
        key: body.key,
        displayName: body.displayName,
        description: body.description,
        isDefault: false,
        current: {
          ...body.design,
          id: alertWorkflowId,
          kind: body.kind,
          version: 1,
          initialState: body.design.states.find((state) => state.initial)!.key,
        },
      }),
    publish: async ({ body }) =>
      versionedWorkflow({
        ...alertWorkflowFixture,
        revision: body.expectedRevision + 1,
        currentVersion: alertWorkflowFixture.currentVersion + 1,
        current: {
          ...body.design,
          id: alertWorkflowId,
          kind: "alert",
          version: alertWorkflowFixture.currentVersion + 1,
          initialState: body.design.states.find((state) => state.initial)!.key,
        },
        updatedAt: "2026-08-26T09:00:00Z",
      }),
    updateMetadata: async ({ body }) =>
      versionedWorkflow({
        ...alertWorkflowFixture,
        displayName: body.displayName,
        description: body.description,
        revision: body.expectedRevision + 1,
        updatedAt: "2026-08-26T09:00:00Z",
      }),
    setDefault: async ({ body }) =>
      versionedWorkflow({
        ...alertWorkflowFixture,
        isDefault: true,
        revision: body.expectedRevision + 1,
        updatedAt: "2026-08-26T09:00:00Z",
      }),
    archive: async ({ body }) =>
      versionedWorkflow({
        ...alertWorkflowFixture,
        isDefault: false,
        status: "archived",
        revision: body.expectedRevision + 1,
        archivedAt: "2026-08-26T09:00:00Z",
        updatedAt: "2026-08-26T09:00:00Z",
      }),
    restore: async ({ body }) =>
      versionedWorkflow({
        ...alertWorkflowFixture,
        isDefault: false,
        status: "active",
        revision: body.expectedRevision + 1,
        updatedAt: "2026-08-26T09:00:00Z",
      }),
    listVersions: async () => ({ items: [alertWorkflowVersionFixture] }),
    simulate: async ({ body }) => ({
      ...workflowSimulationFixture,
      version: body.version,
    }),
  };
  return { ...api, ...overrides };
}
