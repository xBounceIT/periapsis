import type {
  BusinessCalendar,
  OperatorTicketSlaProjection,
  SlaColumn,
  SlaPolicy,
  SlaSimulationResult,
} from "./model";
import type { SlaAdminApi } from "./sla-api";

export const slaTenantId = "01991c20-7d5f-7000-8000-000000000001";
export const slaCalendarId = "01991c20-7d5f-7000-8000-000000000002";
export const slaPolicyId = "01991c20-7d5f-7000-8000-000000000003";
export const slaColumnId = "01991c20-7d5f-7000-8000-000000000004";
export const slaObjectId = "01991c20-7d5f-7000-8000-000000000005";
export const slaInstanceId = "01991c20-7d5f-7000-8000-000000000006";
export const slaMetricInstanceId = "01991c20-7d5f-7000-8000-000000000008";
export const slaMetricDefinitionId = "01991c20-7d5f-7000-8000-000000000009";
export const slaTriggerDefinitionId = "01991c20-7d5f-7000-8000-00000000000a";
export const slaNotificationRuleId = "01991c20-7d5f-7000-8000-00000000000b";

export const calendarFixture: BusinessCalendar = {
  id: slaCalendarId,
  tenantId: slaTenantId,
  key: "rome_business",
  label: "Rome business hours",
  timezone: "Europe/Rome",
  version: 1,
  resourceVersion: 1,
  revisionDigest:
    "1f8fe0d33c8e9ca1f05dcff86e9fe8e70c74723228115db159224389f84be22b",
  createdAt: "2026-08-26T08:00:00Z",
  updatedAt: "2026-08-26T08:00:00Z",
  weeklySchedules: (
    ["monday", "tuesday", "wednesday", "thursday", "friday"] as const
  ).map((weekday) => ({
    weekday,
    intervals: [{ startMinute: 540, endMinute: 1080 }],
  })),
  exceptions: [{ date: "2026-12-25", closed: true, intervals: [] }],
};

export const policyFixture: SlaPolicy = {
  id: slaPolicyId,
  tenantId: slaTenantId,
  key: "critical_response",
  name: "Critical response",
  description: "Critical Alert and Case coverage",
  objectTypes: ["alert", "case"],
  priority: 10,
  matchRule: {
    kind: "predicate",
    predicate: {
      path: { kind: "severity" },
      operator: "one_of",
      values: ["critical", "high"],
    },
  },
  metrics: [
    {
      id: slaMetricDefinitionId,
      key: "first_response",
      label: "First response",
      description: "Initial operator response",
      durationMicros: 1_800_000_000,
      clock: "elapsed",
      startEvent: "ticket.created",
      completionEvent: "response.first",
      resetPolicy: "ignore",
      warning: {
        kind: "remaining_duration",
        remainingMicros: 900_000_000,
      },
      breachGraceMicros: 0,
      displayFormat: "duration",
      customerVisible: true,
      apiVisible: true,
      position: 0,
    },
  ],
  triggers: [
    {
      id: slaTriggerDefinitionId,
      key: "first_response_warning",
      metricDefinitionId: slaMetricDefinitionId,
      kind: "remaining_duration",
      remainingMicros: 900_000_000,
      action: {
        kind: "email",
        configurationId: slaNotificationRuleId,
      },
      position: 0,
    },
  ],
  effectiveFrom: "2026-08-26T08:00:00Z",
  enabled: true,
  applyToSlaEngineSource: false,
  version: 1,
  resourceVersion: 1,
  revisionDigest:
    "2f8fe0d33c8e9ca1f05dcff86e9fe8e70c74723228115db159224389f84be22b",
  createdAt: "2026-08-26T08:10:00Z",
  updatedAt: "2026-08-26T08:10:00Z",
};

export const columnFixture: SlaColumn = {
  id: slaColumnId,
  tenantId: slaTenantId,
  key: "first_response_due",
  label: "First response due",
  metricDefinitionId: slaMetricDefinitionId,
  calculation: "due_at",
  format: "datetime",
  sortable: true,
  filterable: true,
  position: 20,
  customerVisible: true,
  visibleRoleKeys: [],
  styleRules: [{ styleKey: "warning", state: "at_risk" }],
  version: 1,
  resourceVersion: 1,
  revisionDigest:
    "3f8fe0d33c8e9ca1f05dcff86e9fe8e70c74723228115db159224389f84be22b",
  createdAt: "2026-08-26T08:20:00Z",
  updatedAt: "2026-08-26T08:20:00Z",
};

export const simulationFixture: SlaSimulationResult = {
  tenantId: slaTenantId,
  policyId: slaPolicyId,
  policyVersion: 1,
  simulationDigest:
    "7f8fe0d33c8e9ca1f05dcff86e9fe8e70c74723228115db159224389f84be22b",
  metrics: [
    {
      metricDefinitionId: slaMetricDefinitionId,
      metricInstanceId: slaMetricInstanceId,
      metricKey: "first_response",
      state: "at_risk",
      startedAt: "2026-08-26T08:00:00Z",
      dueAt: "2026-08-26T08:30:00Z",
      remainingMicros: 900_000_000,
      consumedPercentage: 50,
      projectedTriggers: [
        {
          triggerDefinitionId: slaTriggerDefinitionId,
          metricDefinitionId: slaMetricDefinitionId,
          action: {
            kind: "email",
            configurationId: slaNotificationRuleId,
          },
          scheduledAt: "2026-08-26T08:15:00Z",
          eventDriven: false,
        },
      ],
    },
  ],
};

export const ticketSlaFixture: OperatorTicketSlaProjection = {
  tenantId: slaTenantId,
  objectType: "case",
  objectId: slaObjectId,
  slaInstanceId,
  aggregateVersion: 3,
  policyId: slaPolicyId,
  policyVersion: 1,
  projectedAt: "2026-08-26T08:15:00Z",
  audience: "operator",
  metrics: [
    {
      metricDefinitionId: slaMetricDefinitionId,
      metricInstanceId: slaMetricInstanceId,
      metricVersion: 2,
      key: "first_response",
      label: "First response",
      state: "at_risk",
      startedAt: "2026-08-26T08:00:00Z",
      dueAt: "2026-08-26T08:30:00Z",
      remainingSeconds: 900,
      consumedPercentage: 50,
      customerVisible: true,
    },
  ],
  columns: [
    {
      columnId: slaColumnId,
      key: "first_response_due",
      label: "First response due",
      calculation: "due_at",
      customerVisible: true,
      state: "at_risk",
      instant: "2026-08-26T08:30:00Z",
      format: "datetime",
      styleKey: "warning",
      materializedAt: "2026-08-26T08:15:00Z",
    },
  ],
};

export function createSlaApiMock(
  overrides: Partial<SlaAdminApi> = {},
): SlaAdminApi {
  const api: SlaAdminApi = {
    listCalendars: async () => ({ items: [calendarFixture] }),
    getCalendar: async () => ({
      etag: '"sla-calendar-v1"',
      value: calendarFixture,
    }),
    createCalendar: async ({ body }) => ({
      etag: '"sla-calendar-v1"',
      value: { ...calendarFixture, ...body },
    }),
    versionCalendar: async ({ body }) => ({
      etag: '"sla-calendar-v2"',
      value: { ...calendarFixture, ...body, version: 2, resourceVersion: 2 },
    }),
    archiveCalendar: async () => ({
      etag: '"sla-calendar-v2"',
      value: {
        ...calendarFixture,
        archivedAt: "2026-08-26T09:00:00Z",
        resourceVersion: 2,
      },
    }),
    listPolicies: async () => ({ items: [policyFixture] }),
    getPolicy: async () => ({ etag: '"sla-policy-v1"', value: policyFixture }),
    createPolicy: async ({ body }) => ({
      etag: '"sla-policy-v1"',
      value: {
        ...policyFixture,
        ...body,
        metrics: body.metrics.map((metric, position) => ({
          ...metric,
          position,
        })),
        triggers: body.triggers.map((trigger, position) => ({
          ...trigger,
          position,
        })),
      },
    }),
    versionPolicy: async ({ body }) => ({
      etag: '"sla-policy-v2"',
      value: {
        ...policyFixture,
        ...body,
        metrics: body.metrics.map((metric, position) => ({
          ...metric,
          position,
        })),
        triggers: body.triggers.map((trigger, position) => ({
          ...trigger,
          position,
        })),
        version: 2,
        resourceVersion: 2,
      },
    }),
    archivePolicy: async () => ({
      etag: '"sla-policy-v2"',
      value: {
        ...policyFixture,
        archivedAt: "2026-08-26T09:00:00Z",
        resourceVersion: 2,
      },
    }),
    listColumns: async () => ({ items: [columnFixture] }),
    getColumn: async () => ({ etag: '"sla-column-v1"', value: columnFixture }),
    createColumn: async ({ body }) => ({
      etag: '"sla-column-v1"',
      value: { ...columnFixture, ...body },
    }),
    versionColumn: async ({ body }) => ({
      etag: '"sla-column-v2"',
      value: { ...columnFixture, ...body, version: 2, resourceVersion: 2 },
    }),
    archiveColumn: async () => ({
      etag: '"sla-column-v2"',
      value: {
        ...columnFixture,
        archivedAt: "2026-08-26T09:00:00Z",
        resourceVersion: 2,
      },
    }),
    simulatePolicy: async ({ body }) => ({
      ...simulationFixture,
      policyVersion: body.policyVersion,
      metrics: simulationFixture.metrics.map((metric, index) => ({
        ...metric,
        metricDefinitionId:
          body.metricBindings[index]?.metricDefinitionId ??
          metric.metricDefinitionId,
        metricInstanceId:
          body.metricBindings[index]?.metricInstanceId ??
          metric.metricInstanceId,
        projectedTriggers: metric.projectedTriggers.map((trigger) => ({
          ...trigger,
          metricDefinitionId:
            body.metricBindings[index]?.metricDefinitionId ??
            trigger.metricDefinitionId,
        })),
      })),
    }),
    getTicketSla: async () => ({
      etag: '"sla-object-v3"',
      value: ticketSlaFixture,
    }),
    overrideTicketSla: async ({ body, kind, objectId, tenantId }) => {
      const policyChange = body.kind === "change_policy";
      const previousVersion = policyChange
        ? body.expectedAggregateVersion
        : body.expectedMetricVersion;
      return {
        projection: {
          etag: '"sla-object-v4"',
          value: {
            ...ticketSlaFixture,
            tenantId,
            objectType: kind,
            objectId,
            aggregateVersion: ticketSlaFixture.aggregateVersion + 1,
            ...(policyChange
              ? {
                  policyId: body.newPolicyId,
                  policyVersion: body.newPolicyVersion,
                }
              : {
                  metrics: ticketSlaFixture.metrics.map((metric) => ({
                    ...metric,
                    metricVersion:
                      metric.metricInstanceId === body.metricInstanceId
                        ? metric.metricVersion + 1
                        : metric.metricVersion,
                  })),
                }),
          },
        },
        receipt: {
          tenantId,
          objectType: kind,
          objectId,
          overrideId: body.overrideId,
          kind: body.kind,
          outcome: policyChange ? "policy_changed" : "metric_updated",
          slaInstanceId: body.slaInstanceId,
          ...(!policyChange ? { metricInstanceId: body.metricInstanceId } : {}),
          previousVersion,
          currentVersion: previousVersion + 1,
          aggregateVersion: ticketSlaFixture.aggregateVersion + 1,
          policyId: policyChange ? body.newPolicyId : ticketSlaFixture.policyId,
          policyVersion: policyChange
            ? body.newPolicyVersion
            : ticketSlaFixture.policyVersion,
          occurredAt: "2026-08-26T08:16:00Z",
          ...(body.kind === "change_calendar" ||
          body.kind === "change_policy" ||
          body.kind === "recalculate"
            ? { simulationDigest: body.simulationDigest }
            : {}),
          replayed: false,
        },
      };
    },
  };
  return { ...api, ...overrides };
}
