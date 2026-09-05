import { describe, expect, it, vi } from "vitest";

import {
  definitionSpecFromDraft,
  draftFromDefinition,
  emptyDefinitionDraft,
} from "./definition-editor-model";
import type { CustomFieldDefinitionView } from "./model";

describe("custom-field definition editor model", () => {
  it("normalizes capabilities and audience-scoped edit policy", () => {
    const draft = {
      ...emptyDefinitionDraft("alert"),
      key: "incident_owner",
      label: "Incident owner",
      customerCreate: true,
      customerUpdate: true,
      customerVisible: false,
      dataType: "structured_json" as const,
      searchable: true,
      sortable: true,
    };

    expect(definitionSpecFromDraft(draft).spec).toMatchObject({
      allowStructuredJson: true,
      editPolicy: { customerCreate: false, customerUpdate: false },
      filterable: false,
      searchable: false,
      sortable: false,
    });
  });

  it("preserves durable option identities and archives removed options", () => {
    const current = definitionFixture();
    const ids = ["0198c97d-cf4f-7000-8000-000000000040"];
    const idFactory = vi.fn(() => ids.shift()!);
    const draft = {
      ...draftFromDefinition(current),
      optionsText: "high | Urgent\nnew | New option",
    };

    const result = definitionSpecFromDraft(draft, current, idFactory);
    expect(result.errors).toEqual([]);
    expect(result.spec?.options).toEqual([
      {
        id: "0198c97d-cf4f-7000-8000-000000000010",
        key: "high",
        label: "Urgent",
        position: 0,
        archived: false,
      },
      {
        id: "0198c97d-cf4f-7000-8000-000000000040",
        key: "new",
        label: "New option",
        position: 1,
        archived: false,
      },
      {
        id: "0198c97d-cf4f-7000-8000-000000000011",
        key: "low",
        label: "Low",
        position: 2,
        archived: true,
      },
    ]);
    expect(idFactory).toHaveBeenCalledTimes(1);
  });

  it("blocks identity changes that require a migration", () => {
    const current = definitionFixture();
    const result = definitionSpecFromDraft(
      { ...draftFromDefinition(current), dataType: "integer" },
      current,
    );
    expect(result.spec).toBeUndefined();
    expect(result.errors.join(" ")).toMatch(/explicit migration/u);
  });
});

function definitionFixture(): CustomFieldDefinitionView {
  return {
    id: "0198c97d-cf4f-7000-8000-000000000002",
    tenantId: "0198c97d-cf4f-7000-8000-000000000001",
    objectType: "alert",
    key: "urgency",
    label: "Urgency",
    description: "",
    dataType: "single_select",
    required: false,
    nullable: false,
    archived: false,
    schemaVersion: 3,
    visibility: { customer: false, operator: true },
    editPolicy: {
      customerCreate: false,
      customerUpdate: false,
      operatorCreate: true,
      operatorUpdate: true,
    },
    placement: {
      showInCreate: true,
      showInDetail: true,
      showInList: true,
      showInExport: true,
    },
    options: [
      {
        id: "0198c97d-cf4f-7000-8000-000000000010",
        key: "high",
        label: "High",
        position: 0,
        archived: false,
      },
      {
        id: "0198c97d-cf4f-7000-8000-000000000011",
        key: "low",
        label: "Low",
        position: 1,
        archived: false,
      },
    ],
    requiredOnTransitions: [],
    searchable: false,
    filterable: true,
    sortable: true,
    allowStructuredJson: false,
  };
}
