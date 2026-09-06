import { describe, expect, it } from "vitest";

import type { WorkflowCondition } from "./model";
import {
  workflowDesignFromDraft,
  workflowDraftFrom,
} from "./workflow-editor-model";

describe("workflow editor input bounds", () => {
  it("rejects deeply nested JSON before recursive schema validation", () => {
    const draft = workflowDraftFrom("alert");
    let condition: WorkflowCondition = {
      kind: "predicate",
      field: "state",
      operator: "equal",
      values: [{ type: "text", value: "new" }],
    };
    for (let depth = 0; depth < 32; depth += 1) {
      condition = { kind: "not", children: [condition] };
    }
    const transitions = [
      {
        key: "close",
        from: "new",
        to: "closed",
        requiredComment: true,
        reopen: false,
        requiredRoles: [],
        requiredPermissions: ["alert.update"],
        requiredCustomFields: [],
        condition,
        effects: ["activity", "audit", "sla"],
      },
    ];

    expect(() =>
      workflowDesignFromDraft({
        ...draft,
        transitionsJson: JSON.stringify(transitions),
      }),
    ).toThrow(/unsupported shape/u);
  });
});
