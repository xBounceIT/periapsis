import type {
  CustomFieldDataType as ContractCustomFieldDataType,
  CustomFieldValue,
} from "@periapsis/contracts";

export const customFieldDataTypes = [
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
] as const satisfies readonly ContractCustomFieldDataType[];

export type CustomFieldDataType = ContractCustomFieldDataType;
export type CustomFieldAudience = "operator" | "customer";
export type CustomFieldObjectType = "alert" | "case";
export type CustomFieldWritePhase = "create" | "update" | "transition";

export const customFieldAdministrationRouteDescriptor = {
  path: "/tenant/custom-fields",
  label: "Custom fields",
  permissions: ["custom_field.read"] as const,
};

export interface CustomFieldOptionView {
  id: string;
  key: string;
  label: string;
  position: number;
  archived: boolean;
}

export interface CustomFieldDefinitionView {
  id: string;
  tenantId: string;
  objectType: CustomFieldObjectType;
  key: string;
  label: string;
  description: string;
  dataType: CustomFieldDataType;
  required: boolean;
  nullable: boolean;
  archived: boolean;
  schemaVersion: number;
  defaultValue?: CustomFieldValue;
  visibility: Readonly<Record<CustomFieldAudience, boolean>>;
  editPolicy: Readonly<{
    customerCreate: boolean;
    customerUpdate: boolean;
    operatorCreate: boolean;
    operatorUpdate: boolean;
  }>;
  placement: Readonly<{
    showInCreate: boolean;
    showInDetail: boolean;
    showInList: boolean;
    showInExport: boolean;
  }>;
  constraints?: Readonly<{
    minimumLength?: number | undefined;
    maximumLength?: number | undefined;
    minimum?: string | undefined;
    maximum?: string | undefined;
    pattern?: string | undefined;
  }>;
  options?: readonly CustomFieldOptionView[];
  requiredOnTransitions: readonly string[];
  searchable: boolean;
  filterable: boolean;
  sortable: boolean;
  allowStructuredJson: boolean;
}

export type CustomFieldDraft =
  | { presence: "missing" }
  | { presence: "null" }
  | { presence: "present"; value: unknown };

export type CustomFieldDrafts = Readonly<Record<string, CustomFieldDraft>>;

export interface CustomFieldValuesResult {
  errors: Readonly<Record<string, string>>;
  values: Readonly<Record<string, CustomFieldValue>>;
}

export function visibleDefinitions(
  definitions: readonly CustomFieldDefinitionView[],
  audience: CustomFieldAudience,
  phase?: CustomFieldWritePhase,
): CustomFieldDefinitionView[] {
  return definitions
    .filter(
      (definition) =>
        !definition.archived &&
        definition.visibility[audience] &&
        (phase === undefined || visibleInPhase(definition, phase)),
    )
    .toSorted((left, right) => codePointCompare(left.key, right.key));
}

export function canEditDefinition(
  definition: CustomFieldDefinitionView,
  audience: CustomFieldAudience,
  phase: CustomFieldWritePhase,
): boolean {
  if (definition.archived || !definition.visibility[audience]) return false;
  if (phase === "create") {
    return audience === "operator"
      ? definition.editPolicy.operatorCreate
      : definition.editPolicy.customerCreate;
  }
  return audience === "operator"
    ? definition.editPolicy.operatorUpdate
    : definition.editPolicy.customerUpdate;
}

export function presentDraft(value: unknown): CustomFieldDraft {
  return { presence: "present", value };
}

export function draftText(draft: CustomFieldDraft | undefined): string {
  if (!draft || draft.presence !== "present") return "";
  if (typeof draft.value === "string") return draft.value;
  if (typeof draft.value === "number") return String(draft.value);
  if (isStructuredValue(draft.value)) {
    try {
      return JSON.stringify(draft.value, null, 2);
    } catch {
      return "";
    }
  }
  return "";
}

export function draftsFromDefaults(
  definitions: readonly CustomFieldDefinitionView[],
  audience: CustomFieldAudience,
): CustomFieldDrafts {
  const drafts: [string, CustomFieldDraft][] = [];
  for (const definition of visibleDefinitions(
    definitions,
    audience,
    "create",
  )) {
    if (
      canEditDefinition(definition, audience, "create") &&
      definition.defaultValue !== undefined
    ) {
      drafts.push([
        definition.key,
        definition.defaultValue === null
          ? { presence: "null" }
          : presentDraft(definition.defaultValue),
      ]);
    }
  }
  return Object.fromEntries(drafts);
}

export function customFieldValuesFromDrafts(
  definitions: readonly CustomFieldDefinitionView[],
  drafts: CustomFieldDrafts,
  audience: CustomFieldAudience,
  phase: CustomFieldWritePhase,
  transitionKey?: string,
): CustomFieldValuesResult {
  const errors: Record<string, string> = {};
  const values: Record<string, CustomFieldValue> = {};
  for (const definition of visibleDefinitions(definitions, audience, phase)) {
    if (!canEditDefinition(definition, audience, phase)) continue;
    const draft = drafts[definition.key] ?? { presence: "missing" };
    const required =
      (phase === "create" && definition.required) ||
      (phase === "transition" &&
        transitionKey !== undefined &&
        definition.requiredOnTransitions.includes(transitionKey));
    if (draft.presence === "missing") {
      if (required && definition.defaultValue === undefined) {
        errors[definition.key] = "This field is required.";
      }
      continue;
    }
    if (draft.presence === "null") {
      if (required) {
        errors[definition.key] = "A required field cannot be empty.";
      } else if (!definition.nullable) {
        errors[definition.key] =
          "This field does not allow an explicit null value.";
      } else {
        values[definition.key] = null;
      }
      continue;
    }
    const normalized = normalizeDraftValue(definition, draft.value, required);
    if (typeof normalized === "string") {
      errors[definition.key] = normalized;
    } else {
      values[definition.key] = normalized.value;
    }
  }
  return {
    errors: sortRecord(errors),
    values: sortRecord(values),
  };
}

export function codePointCompare(left: string, right: string): number {
  const leftPoints = Array.from(
    left,
    (character) => character.codePointAt(0) ?? 0,
  );
  const rightPoints = Array.from(
    right,
    (character) => character.codePointAt(0) ?? 0,
  );
  const length = Math.min(leftPoints.length, rightPoints.length);
  for (let index = 0; index < length; index += 1) {
    const difference = leftPoints[index]! - rightPoints[index]!;
    if (difference !== 0) return difference;
  }
  return leftPoints.length - rightPoints.length;
}

export function safeFieldProblem(status: number): string {
  switch (status) {
    case 403:
      return "Your current access no longer permits this field change.";
    case 409:
      return "The field definition changed while you were editing. Reload the form before retrying.";
    case 412:
    case 428:
      return "This form is stale. Reload the latest version before saving.";
    default:
      return "The custom fields could not be saved. Retry from the latest form.";
  }
}

function visibleInPhase(
  definition: CustomFieldDefinitionView,
  phase: CustomFieldWritePhase,
): boolean {
  return phase === "create"
    ? definition.placement.showInCreate
    : definition.placement.showInDetail;
}

function normalizeDraftValue(
  definition: CustomFieldDefinitionView,
  value: unknown,
  required: boolean,
): { value: CustomFieldValue } | string {
  switch (definition.dataType) {
    case "integer":
    case "duration": {
      const integer = numericValue(value);
      if (
        integer === undefined ||
        !Number.isSafeInteger(integer) ||
        (definition.dataType === "duration" && integer < 0)
      ) {
        return definition.dataType === "duration"
          ? "Enter a whole number of seconds at or above zero."
          : "Enter a whole number.";
      }
      return numericConstraints(definition, integer);
    }
    case "decimal": {
      const decimal = numericValue(value);
      if (decimal === undefined || !Number.isFinite(decimal)) {
        return "Enter a finite decimal number.";
      }
      return numericConstraints(definition, decimal);
    }
    case "boolean":
      return typeof value === "boolean"
        ? { value }
        : "Choose yes or no, or leave the field unset.";
    case "multi_select": {
      if (
        !Array.isArray(value) ||
        !value.every((item) => typeof item === "string")
      ) {
        return "Choose only available options.";
      }
      const live = new Set(
        (definition.options ?? []).flatMap((option) =>
          option.archived ? [] : [option.key],
        ),
      );
      const selected = [...new Set(value)].toSorted(codePointCompare);
      if (selected.some((item) => !live.has(item))) {
        return "One or more selected options are no longer available.";
      }
      if (required && selected.length === 0) {
        return "Choose at least one option.";
      }
      return { value: selected };
    }
    case "single_select": {
      if (typeof value !== "string") return "Choose an available option.";
      const available = (definition.options ?? []).some(
        (option) => !option.archived && option.key === value,
      );
      return available ? { value } : "Choose an available option.";
    }
    case "structured_json": {
      if (!definition.allowStructuredJson) {
        return "Structured JSON is disabled for this definition.";
      }
      if (isStructuredValue(value)) return { value };
      if (
        typeof value !== "string" ||
        new TextEncoder().encode(value).length > 65_536
      ) {
        return "Enter a JSON object no larger than 64 KiB.";
      }
      try {
        const parsed: unknown = JSON.parse(value);
        return isStructuredValue(parsed)
          ? { value: parsed }
          : "Structured JSON must be an object.";
      } catch {
        return "Enter a valid JSON object.";
      }
    }
    case "datetime": {
      if (typeof value !== "string" || value === "") {
        return "Enter a date and time.";
      }
      const instant = new Date(value);
      return Number.isNaN(instant.valueOf())
        ? "Enter a valid date and time."
        : { value: instant.toISOString() };
    }
    case "user":
    case "operator_team":
    case "customer_contact":
    case "asset_reference":
    case "ioc_reference":
      return typeof value === "string" && uuidV7Pattern.test(value)
        ? { value }
        : "Enter a canonical UUIDv7 reference.";
    default: {
      if (typeof value !== "string") return "Enter a text value.";
      if (required && value === "") {
        return "This field cannot be empty.";
      }
      const length = Array.from(value).length;
      if (
        definition.constraints?.minimumLength !== undefined &&
        length < definition.constraints.minimumLength
      ) {
        return `Use at least ${definition.constraints.minimumLength} characters.`;
      }
      if (
        definition.constraints?.maximumLength !== undefined &&
        length > definition.constraints.maximumLength
      ) {
        return `Use no more than ${definition.constraints.maximumLength} characters.`;
      }
      return { value };
    }
  }
}

function numericValue(value: unknown): number | undefined {
  if (typeof value === "number") return value;
  if (typeof value !== "string" || value.trim() === "") return undefined;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : undefined;
}

function numericConstraints(
  definition: CustomFieldDefinitionView,
  value: number,
): { value: number } | string {
  const minimum = Number(definition.constraints?.minimum);
  const maximum = Number(definition.constraints?.maximum);
  if (
    definition.constraints?.minimum !== undefined &&
    Number.isFinite(minimum) &&
    value < minimum
  ) {
    return `Enter a value at or above ${definition.constraints.minimum}.`;
  }
  if (
    definition.constraints?.maximum !== undefined &&
    Number.isFinite(maximum) &&
    value > maximum
  ) {
    return `Enter a value at or below ${definition.constraints.maximum}.`;
  }
  return { value };
}

function isStructuredValue(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function sortRecord<T>(value: Record<string, T>): Record<string, T> {
  return Object.fromEntries(
    Object.entries(value).toSorted(([left], [right]) =>
      codePointCompare(left, right),
    ),
  );
}

const uuidV7Pattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
