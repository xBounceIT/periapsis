import { describe, expect, it } from "vitest";

import {
  normalizeWorkflowDesign,
  normalizeWorkflowSimulation,
  type WorkflowDefinition,
  type WorkflowDesign,
  WorkflowInputError,
  workflowAdministrationRouteDescriptor,
} from "./model";

const workflowId = "01991c20-7d5f-7000-8000-000000000101";

const alertDesign: WorkflowDesign = {
  states: [
    {
      key: "new",
      initial: true,
      terminal: false,
      visibility: "customer",
      actions: [
        { action: "create", effects: ["audit", "activity", "sla"] },
        { action: "claim", effects: ["activity", "audit"] },
      ],
    },
    {
      key: "closed",
      initial: false,
      terminal: true,
      visibility: "customer",
      actions: [],
    },
  ],
  transitions: [
    {
      key: "close",
      from: "new",
      to: "closed",
      requiredComment: true,
      reopen: false,
      requiredRoles: ["senior_analyst"],
      requiredPermissions: ["alert.update"],
      requiredCustomFields: ["resolution"],
      condition: {
        kind: "predicate",
        field: "severity",
        operator: "in",
        values: [
          { type: "text", value: "medium" },
          { type: "text", value: "high" },
        ],
      },
      effects: ["notification", "audit", "activity", "sla"],
    },
  ],
};

describe("workflow administration model", () => {
  it("exports the tenant route with exact live workflow capabilities", () => {
    expect(workflowAdministrationRouteDescriptor).toEqual({
      path: "/tenant/workflows",
      permissions: ["workflow.read"],
    });
  });

  it("canonicalizes the closed workflow design", () => {
    const normalized = normalizeWorkflowDesign("alert", alertDesign);
    expect(normalized.states[1]?.actions[0]?.effects).toEqual([
      "activity",
      "audit",
      "sla",
    ]);
    expect(normalized.transitions[0]?.condition).toMatchObject({
      values: [
        { type: "text", value: "high" },
        { type: "text", value: "medium" },
      ],
    });
  });

  it("omits an absent optional condition from the canonical transition", () => {
    const normalized = normalizeWorkflowDesign("alert", {
      ...alertDesign,
      transitions: [{ ...alertDesign.transitions[0]!, condition: undefined }],
    });

    expect(normalized.transitions[0]).not.toHaveProperty("condition");
  });

  it("uses kernel-compatible ordering and canonical instants", () => {
    const normalized = normalizeWorkflowDesign("alert", {
      ...alertDesign,
      transitions: [
        {
          ...alertDesign.transitions[0]!,
          requiredRoles: ["team_a", "team-a"],
          requiredPermissions: ["alert.assign", "alert.update"],
          condition: {
            kind: "predicate",
            field: "custom.risk.score",
            operator: "in",
            values: [
              { type: "number", value: 10 },
              { type: "number", value: 2 },
            ],
          },
        },
      ],
    });

    expect(normalized.transitions[0]?.requiredRoles).toEqual([
      "team-a",
      "team_a",
    ]);
    expect(normalized.transitions[0]?.requiredPermissions).toEqual([
      "alert.update",
      "alert.assign",
    ]);
    expect(normalized.transitions[0]?.condition).toMatchObject({
      field: "custom.risk.score",
      values: [
        { type: "number", value: 2 },
        { type: "number", value: 10 },
      ],
    });

    const instant = normalizeWorkflowDesign("alert", {
      ...alertDesign,
      transitions: [
        {
          ...alertDesign.transitions[0]!,
          condition: {
            kind: "predicate",
            field: "detected_at",
            operator: "greater_than",
            values: [
              {
                type: "instant",
                value: "2026-08-26T10:00:00.123456789+02:00",
              },
            ],
          },
        },
      ],
    });
    expect(instant.transitions[0]?.condition).toMatchObject({
      values: [{ type: "instant", value: "2026-08-26T08:00:00.123456Z" }],
    });
  });

  it("keeps dotted condition suffixes but rejects dotted workflow keys", () => {
    expect(() =>
      normalizeWorkflowDesign("alert", {
        ...alertDesign,
        states: alertDesign.states.map((state) =>
          state.key === "new" ? { ...state, key: "new.state" } : state,
        ),
        transitions: [{ ...alertDesign.transitions[0]!, from: "new.state" }],
      }),
    ).toThrow(/canonical key/u);

    expect(() =>
      normalizeWorkflowDesign("alert", {
        ...alertDesign,
        transitions: [
          {
            ...alertDesign.transitions[0]!,
            condition: {
              kind: "predicate",
              field: "tag.customer.priority",
              operator: "equal",
              values: [{ type: "boolean", value: true }],
            },
          },
        ],
      }),
    ).not.toThrow();
  });

  it("rejects unreachable states and cross-kind permissions", () => {
    expect(() =>
      normalizeWorkflowDesign("alert", {
        ...alertDesign,
        states: [
          ...alertDesign.states,
          {
            key: "isolated",
            initial: false,
            terminal: true,
            visibility: "internal",
            actions: [],
          },
        ],
      }),
    ).toThrow(/reachable/u);
    expect(() =>
      normalizeWorkflowDesign("alert", {
        ...alertDesign,
        transitions: [
          {
            ...alertDesign.transitions[0]!,
            requiredPermissions: ["case.transition"],
          },
        ],
      }),
    ).toThrow(/another ticket kind/u);
  });

  it("enforces fail-closed condition shape and scalar types", () => {
    expect(() =>
      normalizeWorkflowDesign("alert", {
        ...alertDesign,
        transitions: [
          {
            ...alertDesign.transitions[0]!,
            condition: {
              kind: "not",
              children: [
                {
                  kind: "predicate",
                  field: "customer_visible",
                  operator: "equal",
                  values: [{ type: "text", value: "true" }],
                },
              ],
            },
          },
        ],
      }),
    ).toThrow(/wrong scalar type/u);
    expect(() =>
      normalizeWorkflowDesign("alert", {
        ...alertDesign,
        transitions: [
          {
            ...alertDesign.transitions[0]!,
            condition: {
              kind: "all",
              children: [alertDesign.transitions[0]!.condition!],
            },
          },
        ],
      }),
    ).toThrow(WorkflowInputError);
  });

  it("rejects simulator facts that attempt to override derived state", () => {
    const design = normalizeWorkflowDesign("alert", alertDesign);
    const workflow: WorkflowDefinition = {
      ...design,
      id: workflowId,
      kind: "alert",
      version: 1,
      initialState: "new",
    };
    expect(() =>
      normalizeWorkflowSimulation("alert", workflow, {
        version: 1,
        state: "new",
        commentPresent: false,
        roles: [],
        permissions: [],
        providedCustomFields: [],
        facts: [{ field: "state", value: { type: "text", value: "closed" } }],
      }),
    ).toThrow(/derived facts/u);
  });

  it("supports the current-version sentinel and defers pinned-history state checks", () => {
    const design = normalizeWorkflowDesign("alert", alertDesign);
    const workflow: WorkflowDefinition = {
      ...design,
      id: workflowId,
      kind: "alert",
      version: 2,
      initialState: "new",
    };
    expect(
      normalizeWorkflowSimulation("alert", workflow, {
        version: 0,
        state: "new",
        commentPresent: false,
        roles: [],
        permissions: ["alert.assign", "alert.update"],
        providedCustomFields: [],
        facts: [],
      }),
    ).toMatchObject({
      permissions: ["alert.update", "alert.assign"],
      version: 0,
    });
    expect(() =>
      normalizeWorkflowSimulation("case", workflow, {
        version: 0,
        state: "new",
        commentPresent: false,
        roles: [],
        permissions: [],
        providedCustomFields: [],
        facts: [],
      }),
    ).toThrow(/does not match/u);
    expect(() =>
      normalizeWorkflowSimulation("alert", workflow, {
        version: 1,
        state: "legacy_state",
        commentPresent: false,
        roles: [],
        permissions: [],
        providedCustomFields: [],
        facts: [],
      }),
    ).not.toThrow();
    expect(() =>
      normalizeWorkflowSimulation("alert", workflow, {
        version: 2,
        state: "legacy_state",
        commentPresent: false,
        roles: [],
        permissions: [],
        providedCustomFields: [],
        facts: [],
      }),
    ).toThrow(/does not exist/u);
  });

  it("rejects typed simulator facts that conflict with closed fact kinds", () => {
    const design = normalizeWorkflowDesign("alert", alertDesign);
    const workflow: WorkflowDefinition = {
      ...design,
      id: workflowId,
      kind: "alert",
      version: 1,
      initialState: "new",
    };
    expect(() =>
      normalizeWorkflowSimulation("alert", workflow, {
        version: 1,
        state: "new",
        commentPresent: false,
        roles: [],
        permissions: [],
        providedCustomFields: [],
        facts: [{ field: "tag.vip", value: { type: "text", value: "true" } }],
      }),
    ).toThrow(/wrong scalar type/u);
  });
});
