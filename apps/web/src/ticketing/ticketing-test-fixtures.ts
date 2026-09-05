import type {
  AlertCustomerProjection,
  AlertOperatorProjection,
  CaseOperatorProjection,
  SavedTicketView,
} from "@periapsis/contracts";

import type { TicketingApi } from "../lib/ticketing-api";

export const tenantId = "0198c97d-cf4f-7000-8000-000000000010";
export const alertId = "0198c97d-cf4f-7000-8000-000000000011";
export const caseId = "0198c97d-cf4f-7000-8000-000000000012";
export const teamId = "0198c97d-cf4f-7000-8000-000000000013";
export const userId = "0198c97d-cf4f-7000-8000-000000000014";
export const membershipId = "0198c97d-cf4f-7000-8000-000000000015";
export const workflowId = "0198c97d-cf4f-7000-8000-000000000016";
export const savedViewId = "0198c97d-cf4f-7000-8000-000000000020";
export const customDefinitionId = "0198c97d-cf4f-7000-8000-000000000021";
export const slaDefinitionId = "0198c97d-cf4f-7000-8000-000000000022";

export const operatorAlert = {
  projection: "operator",
  id: alertId,
  tenantId,
  alertNumber: "ALT-2026-0042",
  source: "sentinel",
  sourceType: "siem",
  title: "Suspicious PowerShell chain",
  description:
    "Observed **encoded command** execution on the finance endpoint.",
  workflow: {
    workflowId,
    kind: "alert",
    version: 3,
    stateKey: "new",
    initial: true,
    terminal: false,
    customerVisible: true,
  },
  severity: "high",
  priority: "urgent",
  category: "endpoint",
  detectedAt: "2026-08-25T08:10:00Z",
  receivedAt: "2026-08-25T08:11:00Z",
  assignment: {
    assignedTeamId: teamId,
    assigneeUserId: null,
    claimedAt: null,
    claimedBy: null,
  },
  visibility: "customer",
  customerVisible: true,
  tags: ["powershell", "windows"],
  customFields: { host: "fin-ws-04" },
  creator: { principalType: "human", membershipId },
  availableTransitions: [
    {
      transitionKey: "start_investigation",
      targetStateKey: "investigating",
      commentRequired: false,
      requiredCustomFieldKeys: [],
    },
  ],
  version: 1,
  createdAt: "2026-08-25T08:11:00Z",
  updatedAt: "2026-08-25T08:11:00Z",
} satisfies AlertOperatorProjection;

export const claimedAlert = {
  ...operatorAlert,
  workflow: {
    ...operatorAlert.workflow,
    initial: false,
    stateKey: "investigating",
  },
  assignment: {
    ...operatorAlert.assignment,
    claimedAt: "2026-08-25T08:13:00Z",
    claimedBy: userId,
  },
  version: 2,
  updatedAt: "2026-08-25T08:13:00Z",
} satisfies AlertOperatorProjection;

export const operatorAlertWithDynamicColumns = {
  ...operatorAlert,
  dynamicColumns: [
    {
      source: "custom_field",
      definitionId: customDefinitionId,
      definitionVersion: 4,
      value: "finance",
    },
    {
      source: "sla",
      definitionId: slaDefinitionId,
      definitionVersion: 2,
      value: "37",
      styleKey: "at_risk",
      materializedAt: "2026-08-25T08:12:00Z",
    },
  ],
} satisfies AlertOperatorProjection;

const digest = "a".repeat(64);

export const savedAlertView = {
  id: savedViewId,
  tenantId,
  ownerMembershipId: membershipId,
  kind: "alert",
  name: "Finance at risk",
  status: "active",
  revision: 3,
  spec: {
    filters: {
      states: ["new"],
      severities: ["high"],
      priorities: ["urgent"],
      queue: "my_operator_teams",
      custom: [
        {
          definition: {
            id: customDefinitionId,
            tenantId,
            kind: "alert",
            key: "business_unit",
            version: 4,
            sha256: digest,
          },
          dataType: "short_text",
          operator: "equal",
          value: "finance",
        },
      ],
    },
    sort: {
      source: "sla",
      definition: {
        id: slaDefinitionId,
        tenantId,
        kind: "alert",
        key: "response_budget",
        version: 2,
        sha256: "b".repeat(64),
      },
      direction: "asc",
      nulls: "last",
    },
    columns: [
      {
        source: "core",
        coreKey: "ticket",
        width: 340,
        visible: true,
        pin: "start",
      },
      {
        source: "custom_field",
        definition: {
          id: customDefinitionId,
          tenantId,
          kind: "alert",
          key: "business_unit",
          version: 4,
          sha256: digest,
        },
        width: 180,
        visible: true,
        pin: "none",
      },
      {
        source: "sla",
        definition: {
          id: slaDefinitionId,
          tenantId,
          kind: "alert",
          key: "response_budget",
          version: 2,
          sha256: "b".repeat(64),
        },
        width: 200,
        visible: true,
        pin: "end",
      },
    ],
  },
  specSha256: "c".repeat(64),
  createdAt: "2026-08-25T08:00:00Z",
  updatedAt: "2026-08-25T08:12:00Z",
} satisfies SavedTicketView;

export const operatorCase = {
  projection: "operator",
  id: caseId,
  tenantId,
  caseNumber: "CASE-2026-0007",
  title: "Finance endpoint investigation",
  summary: "Escalated endpoint signal",
  description: "Investigate the encoded command chain.",
  workflow: {
    workflowId,
    kind: "case",
    version: 2,
    stateKey: "open",
    initial: true,
    terminal: false,
    customerVisible: true,
  },
  severity: "high",
  priority: "urgent",
  category: "endpoint",
  detectionTime: "2026-08-25T08:10:00Z",
  openedAt: "2026-08-25T08:15:00Z",
  assignment: {
    assignedTeamId: teamId,
    assigneeUserId: null,
    claimedAt: null,
    claimedBy: null,
  },
  visibility: "customer",
  customerVisible: true,
  tags: ["powershell", "windows"],
  customFields: {},
  creator: { principalType: "human", membershipId },
  availableTransitions: [],
  version: 1,
  createdAt: "2026-08-25T08:15:00Z",
  updatedAt: "2026-08-25T08:15:00Z",
} satisfies CaseOperatorProjection;

export const customerAlert = {
  projection: "customer",
  id: alertId,
  tenantId,
  alertNumber: "ALT-2026-0042",
  title: "Suspicious endpoint activity",
  description:
    "Review `<img src=x onerror=alert(1)>` and [unsafe](javascript:alert(1)).",
  workflow: {
    workflowId,
    kind: "alert",
    version: 3,
    stateKey: "investigating",
    initial: false,
    terminal: false,
    customerVisible: true,
  },
  severity: "high",
  priority: "urgent",
  category: "endpoint",
  detectedAt: "2026-08-25T08:10:00Z",
  receivedAt: "2026-08-25T08:11:00Z",
  visibility: "customer",
  customerVisible: true,
  tags: ["endpoint"],
  customFields: { public_reference: "IR-42" },
  version: 2,
  createdAt: "2026-08-25T08:11:00Z",
  updatedAt: "2026-08-25T08:13:00Z",
} satisfies AlertCustomerProjection;

const unsupported = async (): Promise<never> => {
  throw new Error("Unexpected TicketingApi call in test");
};

export function createTicketingApi(
  overrides: Partial<TicketingApi> = {},
): TicketingApi {
  return {
    createAlert: unsupported,
    createCase: unsupported,
    createComment: unsupported,
    previewComment: unsupported,
    listCommentMentionCandidates: unsupported,
    editComment: unsupported,
    listCommentRevisions: unsupported,
    deleteAlert: unsupported,
    escalateAlert: unsupported,
    unlinkAlertCase: unsupported,
    getTicket: unsupported,
    listActivities: unsupported,
    listActivityFeed: unsupported,
    listAlertContactLinks: unsupported,
    listComments: unsupported,
    listLinks: unsupported,
    listSavedTicketViews: async () => ({ items: [] }),
    listTickets: unsupported,
    getSavedTicketView: unsupported,
    createSavedTicketView: unsupported,
    replaceSavedTicketView: unsupported,
    archiveSavedTicketView: unsupported,
    restoreSavedTicketView: unsupported,
    mutateTicket: unsupported,
    ...overrides,
  };
}
