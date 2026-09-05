import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { DynamicFieldForm } from "./dynamic-field-form";
import {
  customFieldDataTypes,
  customFieldValuesFromDrafts,
  safeFieldProblem,
  type CustomFieldDefinitionView,
} from "./model";

const visibleText: CustomFieldDefinitionView = {
  id: "019d0200-0001-7001-8001-000000000001",
  tenantId: "019d0200-0000-7000-8000-000000000000",
  objectType: "case",
  key: "triage_code",
  label: "Triage code",
  description: "Customer-safe incident classification.",
  dataType: "short_text",
  required: true,
  nullable: true,
  archived: false,
  schemaVersion: 1,
  visibility: { operator: true, customer: true },
  editPolicy: {
    customerCreate: true,
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
  requiredOnTransitions: [],
  searchable: true,
  filterable: true,
  sortable: true,
  allowStructuredJson: false,
};

afterEach(cleanup);

describe("DynamicFieldForm", () => {
  it("projects customer-visible definitions and preserves missing, null, and present", () => {
    const onChange = vi.fn();
    const hidden = {
      ...visibleText,
      id: "019d0200-0002-7002-8002-000000000002",
      key: "operator_notes",
      label: "Operator notes",
      visibility: { operator: true, customer: false },
    };
    render(
      <DynamicFieldForm
        definitions={[hidden, visibleText]}
        drafts={{}}
        audience="customer"
        phase="create"
        onChange={onChange}
      />,
    );

    expect(screen.queryByLabelText("Operator notes")).not.toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Triage code"), {
      target: { value: "P1" },
    });
    expect(onChange).toHaveBeenLastCalledWith("triage_code", {
      presence: "present",
      value: "P1",
    });
    fireEvent.click(screen.getByLabelText("Store an explicit empty value"));
    expect(onChange).toHaveBeenLastCalledWith("triage_code", {
      presence: "null",
    });
  });

  it("renders server-authoritative read-only state and field errors accessibly", () => {
    const onChange = vi.fn();
    render(
      <DynamicFieldForm
        definitions={[visibleText]}
        drafts={{ triage_code: { presence: "present", value: "P2" } }}
        audience="customer"
        phase="update"
        errors={{
          triage_code: "The current workflow requires a different value.",
        }}
        onChange={onChange}
      />,
    );
    expect(screen.getByLabelText("Triage code")).toBeDisabled();
    expect(screen.getByText("Read only")).toBeInTheDocument();
    expect(screen.queryByText("Required")).not.toBeInTheDocument();
    expect(screen.getByRole("alert")).toHaveTextContent("current workflow");
    expect(onChange).not.toHaveBeenCalled();
  });

  it("maps concurrency and permission failures without reflecting server detail", () => {
    expect(safeFieldProblem(403)).toMatch(/access no longer permits/u);
    expect(safeFieldProblem(409)).toMatch(/definition changed/u);
    expect(safeFieldProblem(412)).toMatch(/stale/u);
    expect(safeFieldProblem(428)).toBe(safeFieldProblem(412));
    expect(safeFieldProblem(500)).not.toContain("database");
  });

  it("tracks the complete canonical contract vocabulary", () => {
    expect(customFieldDataTypes).toEqual([
      "short_text",
      "long_text",
      "integer",
      "decimal",
      "boolean",
      "date",
      "datetime",
      "duration",
      "single_select",
      "multi_select",
      "url",
      "email",
      "ip",
      "cidr",
      "user",
      "operator_team",
      "customer_contact",
      "asset_reference",
      "ioc_reference",
      "structured_json",
    ]);
  });

  it("serializes typed values, explicit empty text, and RFC3339 datetimes", () => {
    const definitions: CustomFieldDefinitionView[] = [
      visibleText,
      {
        ...visibleText,
        id: "019d0200-0002-7002-8002-000000000002",
        key: "count",
        label: "Count",
        dataType: "integer",
        required: false,
      },
      {
        ...visibleText,
        id: "019d0200-0003-7003-8003-000000000003",
        key: "observed_at",
        label: "Observed at",
        dataType: "datetime",
        required: false,
      },
    ];
    const result = customFieldValuesFromDrafts(
      definitions,
      {
        triage_code: { presence: "present", value: "" },
        count: { presence: "present", value: "42" },
        observed_at: { presence: "present", value: "2026-08-30T10:15" },
      },
      "operator",
      "create",
    );

    expect(result.errors).toEqual({
      triage_code: "This field cannot be empty.",
    });
    expect(result.values.count).toBe(42);
    expect(result.values.observed_at).toMatch(/^2026-08-30T/u);
    expect(result.values).not.toHaveProperty("triage_code");
  });

  it("never submits hidden, read-only, or non-create-placement values", () => {
    const result = customFieldValuesFromDrafts(
      [
        { ...visibleText, visibility: { customer: false, operator: true } },
        {
          ...visibleText,
          id: "019d0200-0002-7002-8002-000000000002",
          key: "detail_only",
          placement: { ...visibleText.placement, showInCreate: false },
        },
        {
          ...visibleText,
          id: "019d0200-0003-7003-8003-000000000003",
          key: "read_only",
          editPolicy: { ...visibleText.editPolicy, customerCreate: false },
        },
      ],
      {
        triage_code: { presence: "present", value: "secret" },
        detail_only: { presence: "present", value: "secret" },
        read_only: { presence: "present", value: "secret" },
      },
      "customer",
      "create",
    );

    expect(result).toEqual({ errors: {}, values: {} });
  });

  it("applies required semantics by write phase rather than by definition alone", () => {
    const result = customFieldValuesFromDrafts(
      [visibleText],
      { triage_code: { presence: "present", value: "" } },
      "operator",
      "update",
    );

    expect(result).toEqual({ errors: {}, values: { triage_code: "" } });
  });

  it("makes update removal explicit and restores the projected baseline", () => {
    const onChange = vi.fn();
    const baseline = {
      triage_code: { presence: "present" as const, value: "P2" },
    };
    const view = render(
      <DynamicFieldForm
        audience="operator"
        baselineDrafts={baseline}
        definitions={[visibleText]}
        drafts={baseline}
        onChange={onChange}
        phase="update"
      />,
    );

    fireEvent.click(screen.getByLabelText("Store a value for Triage code"));
    expect(onChange).toHaveBeenLastCalledWith("triage_code", {
      presence: "missing",
    });

    view.rerender(
      <DynamicFieldForm
        audience="operator"
        baselineDrafts={baseline}
        definitions={[visibleText]}
        drafts={{ triage_code: { presence: "missing" } }}
        onChange={onChange}
        phase="update"
      />,
    );
    fireEvent.click(screen.getByLabelText("Store a value for Triage code"));
    expect(onChange).toHaveBeenLastCalledWith(
      "triage_code",
      baseline.triage_code,
    );
  });

  it("projects RFC3339 instants into a datetime-local control", () => {
    render(
      <DynamicFieldForm
        definitions={[
          {
            ...visibleText,
            dataType: "datetime",
            key: "observed_at",
            label: "Observed at",
          },
        ]}
        drafts={{
          observed_at: {
            presence: "present",
            value: "2026-08-30T10:15:00.000Z",
          },
        }}
        audience="operator"
        phase="create"
        onChange={vi.fn()}
      />,
    );

    expect(
      screen.getByLabelText<HTMLInputElement>("Observed at").value,
    ).toMatch(/^2026-08-30T\d{2}:15$/u);
  });
});
