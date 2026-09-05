import type { CustomFieldDefinitionSpec } from "@periapsis/contracts";

import { generateUuidV7 } from "../lib/uuid-v7";
import {
  codePointCompare,
  type CustomFieldDataType,
  type CustomFieldDefinitionView,
  type CustomFieldObjectType,
  type CustomFieldOptionView,
} from "./model";

export interface CustomFieldDefinitionDraft {
  allowStructuredJson: boolean;
  customerCreate: boolean;
  customerUpdate: boolean;
  customerVisible: boolean;
  dataType: CustomFieldDataType;
  description: string;
  filterable: boolean;
  key: string;
  label: string;
  maximum: string;
  maximumLength: string;
  minimum: string;
  minimumLength: string;
  nullable: boolean;
  objectType: CustomFieldObjectType;
  operatorCreate: boolean;
  operatorUpdate: boolean;
  operatorVisible: boolean;
  optionsText: string;
  pattern: string;
  required: boolean;
  requiredOnTransitions: string;
  searchable: boolean;
  showInCreate: boolean;
  showInDetail: boolean;
  showInExport: boolean;
  showInList: boolean;
  sortable: boolean;
}

export interface DefinitionDraftResult {
  errors: readonly string[];
  spec?: CustomFieldDefinitionSpec;
}

export function emptyDefinitionDraft(
  objectType: CustomFieldObjectType,
): CustomFieldDefinitionDraft {
  return {
    allowStructuredJson: false,
    customerCreate: false,
    customerUpdate: false,
    customerVisible: false,
    dataType: "short_text",
    description: "",
    filterable: true,
    key: "",
    label: "",
    maximum: "",
    maximumLength: "",
    minimum: "",
    minimumLength: "",
    nullable: false,
    objectType,
    operatorCreate: true,
    operatorUpdate: true,
    operatorVisible: true,
    optionsText: "",
    pattern: "",
    required: false,
    requiredOnTransitions: "",
    searchable: true,
    showInCreate: true,
    showInDetail: true,
    showInExport: true,
    showInList: true,
    sortable: true,
  };
}

export function draftFromDefinition(
  definition: CustomFieldDefinitionView,
): CustomFieldDefinitionDraft {
  return {
    allowStructuredJson: definition.allowStructuredJson,
    customerCreate: definition.editPolicy.customerCreate,
    customerUpdate: definition.editPolicy.customerUpdate,
    customerVisible: definition.visibility.customer,
    dataType: definition.dataType,
    description: definition.description,
    filterable: definition.filterable,
    key: definition.key,
    label: definition.label,
    maximum: definition.constraints?.maximum ?? "",
    maximumLength: numberText(definition.constraints?.maximumLength),
    minimum: definition.constraints?.minimum ?? "",
    minimumLength: numberText(definition.constraints?.minimumLength),
    nullable: definition.nullable,
    objectType: definition.objectType,
    operatorCreate: definition.editPolicy.operatorCreate,
    operatorUpdate: definition.editPolicy.operatorUpdate,
    operatorVisible: definition.visibility.operator,
    optionsText: (definition.options ?? [])
      .filter((option) => !option.archived)
      .toSorted((left, right) => left.position - right.position)
      .map((option) => `${option.key} | ${option.label}`)
      .join("\n"),
    pattern: definition.constraints?.pattern ?? "",
    required: definition.required,
    requiredOnTransitions: definition.requiredOnTransitions.join(", "),
    searchable: definition.searchable,
    showInCreate: definition.placement.showInCreate,
    showInDetail: definition.placement.showInDetail,
    showInExport: definition.placement.showInExport,
    showInList: definition.placement.showInList,
    sortable: definition.sortable,
  };
}

export function definitionSpecFromDraft(
  draft: CustomFieldDefinitionDraft,
  current?: CustomFieldDefinitionView,
  idFactory: () => string = generateUuidV7,
): DefinitionDraftResult {
  const errors: string[] = [];
  const key = draft.key.trim();
  const label = draft.label.trim();
  const description = draft.description.trim();
  if (!keyPattern.test(key)) {
    errors.push(
      "Key must start with a lowercase letter and use at most 64 lowercase letters, digits, dots, underscores, or hyphens.",
    );
  }
  if (!label || label.length > 256) {
    errors.push("Label must contain 1–256 characters.");
  }
  if (description.length > 8192) {
    errors.push("Description must contain at most 8,192 characters.");
  }
  if (!draft.operatorVisible && !draft.customerVisible) {
    errors.push("At least one audience must be able to see the field.");
  }
  if (
    current &&
    (current.key !== key ||
      current.objectType !== draft.objectType ||
      current.dataType !== draft.dataType)
  ) {
    errors.push(
      "Key, object type, and data type are immutable in this editor because stored values require an explicit migration.",
    );
  }

  const requiredOnTransitions = stableKeys(draft.requiredOnTransitions);
  if (requiredOnTransitions.length > 128) {
    errors.push("Use no more than 128 transition keys.");
  }
  const invalidTransition = requiredOnTransitions.find(
    (transition) => !keyPattern.test(transition),
  );
  if (invalidTransition) {
    errors.push(`Transition key ${invalidTransition} is not canonical.`);
  }

  const constraints = definitionConstraints(draft, errors);
  const options = definitionOptions(
    draft,
    current?.options ?? [],
    idFactory,
    errors,
  );
  const searchable = searchableTypes.has(draft.dataType) && draft.searchable;
  const sortable = sortableTypes.has(draft.dataType) && draft.sortable;
  const filterable = draft.dataType !== "structured_json" && draft.filterable;
  const allowStructuredJson = draft.dataType === "structured_json";

  if (errors.length > 0) return { errors };
  const spec: CustomFieldDefinitionSpec = {
    objectType: draft.objectType,
    key,
    label,
    description,
    dataType: draft.dataType,
    required: draft.required,
    nullable: draft.nullable,
    ...(current?.defaultValue === undefined
      ? {}
      : { defaultValue: current.defaultValue }),
    ...(constraints ? { constraints } : {}),
    ...(options ? { options } : {}),
    visibility: {
      customer: draft.customerVisible,
      operator: draft.operatorVisible,
    },
    editPolicy: {
      customerCreate: draft.customerVisible && draft.customerCreate,
      customerUpdate: draft.customerVisible && draft.customerUpdate,
      operatorCreate: draft.operatorVisible && draft.operatorCreate,
      operatorUpdate: draft.operatorVisible && draft.operatorUpdate,
    },
    placement: {
      showInCreate: draft.showInCreate,
      showInDetail: draft.showInDetail,
      showInList: draft.showInList,
      showInExport: draft.showInExport,
    },
    requiredOnTransitions,
    searchable,
    filterable,
    sortable,
    allowStructuredJson,
  };
  return { errors: [], spec };
}

export function humanizeDataType(dataType: CustomFieldDataType): string {
  return dataType
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

export function supportsSearch(dataType: CustomFieldDataType): boolean {
  return searchableTypes.has(dataType);
}

export function supportsSort(dataType: CustomFieldDataType): boolean {
  return sortableTypes.has(dataType);
}

export function supportsTextConstraints(
  dataType: CustomFieldDataType,
): boolean {
  return ["short_text", "long_text", "url", "email"].includes(dataType);
}

export function supportsNumericConstraints(
  dataType: CustomFieldDataType,
): boolean {
  return ["integer", "decimal", "duration"].includes(dataType);
}

export function isSelectType(dataType: CustomFieldDataType): boolean {
  return dataType === "single_select" || dataType === "multi_select";
}

function definitionConstraints(
  draft: CustomFieldDefinitionDraft,
  errors: string[],
): CustomFieldDefinitionSpec["constraints"] | undefined {
  if (supportsTextConstraints(draft.dataType)) {
    const minimumLength = optionalInteger(draft.minimumLength, 0, 65_536);
    const maximumLength = optionalInteger(draft.maximumLength, 0, 65_536);
    if (minimumLength === null || maximumLength === null) {
      errors.push(
        "Text length limits must be whole numbers between 0 and 65,536.",
      );
    }
    if (
      typeof minimumLength === "number" &&
      typeof maximumLength === "number" &&
      minimumLength > maximumLength
    ) {
      errors.push("Minimum length cannot exceed maximum length.");
    }
    const pattern = draft.pattern.trim();
    if (pattern.length > 512)
      errors.push("Pattern must contain at most 512 characters.");
    if (pattern) {
      try {
        const compiledPattern = new RegExp(pattern, "u");
        void compiledPattern;
      } catch {
        errors.push("Pattern must be a valid regular expression.");
      }
    }
    const value = {
      ...(typeof minimumLength === "number" ? { minimumLength } : {}),
      ...(typeof maximumLength === "number" ? { maximumLength } : {}),
      ...(pattern ? { pattern } : {}),
    };
    return Object.keys(value).length > 0 ? value : undefined;
  }
  if (supportsNumericConstraints(draft.dataType)) {
    const minimum = draft.minimum.trim();
    const maximum = draft.maximum.trim();
    if (minimum && !decimalPattern.test(minimum))
      errors.push("Minimum must be a canonical decimal.");
    if (maximum && !decimalPattern.test(maximum))
      errors.push("Maximum must be a canonical decimal.");
    if (
      (draft.dataType === "integer" || draft.dataType === "duration") &&
      (minimum.includes(".") || maximum.includes("."))
    ) {
      errors.push("Integer and duration bounds cannot contain decimals.");
    }
    if (minimum && maximum && Number(minimum) > Number(maximum)) {
      errors.push("Minimum cannot exceed maximum.");
    }
    const value = {
      ...(minimum ? { minimum } : {}),
      ...(maximum ? { maximum } : {}),
    };
    return Object.keys(value).length > 0 ? value : undefined;
  }
  return undefined;
}

function definitionOptions(
  draft: CustomFieldDefinitionDraft,
  current: readonly CustomFieldOptionView[],
  idFactory: () => string,
  errors: string[],
): CustomFieldDefinitionSpec["options"] | undefined {
  if (!isSelectType(draft.dataType)) return undefined;
  const liveInputs = draft.optionsText
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const separator = line.indexOf("|");
      return separator < 0
        ? { key: line.trim(), label: line.trim() }
        : {
            key: line.slice(0, separator).trim(),
            label: line.slice(separator + 1).trim(),
          };
    });
  if (liveInputs.length === 0)
    errors.push("Select fields require at least one live option.");
  if (liveInputs.length > 512) errors.push("Use no more than 512 options.");
  const seen = new Set<string>();
  for (const option of liveInputs) {
    if (
      !keyPattern.test(option.key) ||
      !option.label ||
      option.label.length > 256
    ) {
      errors.push(
        "Each option must use `key | Label` with a canonical key and a 1–256 character label.",
      );
      break;
    }
    if (seen.has(option.key)) {
      errors.push(`Option key ${option.key} is duplicated.`);
      break;
    }
    seen.add(option.key);
  }
  const currentByKey = new Map(current.map((option) => [option.key, option]));
  const live = liveInputs.map((option, position) => ({
    id: currentByKey.get(option.key)?.id ?? idFactory(),
    key: option.key,
    label: option.label,
    position,
    archived: false,
  }));
  const archived = current
    .filter((option) => !seen.has(option.key))
    .map((option, index) => ({
      ...option,
      position: live.length + index,
      archived: true,
    }));
  return [...live, ...archived];
}

function stableKeys(value: string): string[] {
  return [
    ...new Set(
      value
        .split(/[\s,]+/u)
        .map((item) => item.trim())
        .filter(Boolean),
    ),
  ].toSorted(codePointCompare);
}

function optionalInteger(
  value: string,
  minimum: number,
  maximum: number,
): number | null | undefined {
  if (!value.trim()) return undefined;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed >= minimum && parsed <= maximum
    ? parsed
    : null;
}

function numberText(value: number | undefined): string {
  return value === undefined ? "" : String(value);
}

const keyPattern = /^[a-z][a-z0-9_.-]{0,63}$/u;
const decimalPattern = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$/u;
const searchableTypes = new Set<CustomFieldDataType>([
  "short_text",
  "long_text",
  "url",
  "email",
  "ip",
  "cidr",
]);
const sortableTypes = new Set<CustomFieldDataType>([
  "short_text",
  "integer",
  "decimal",
  "boolean",
  "date",
  "datetime",
  "duration",
  "single_select",
  "url",
  "email",
  "ip",
  "cidr",
  "user",
  "operator_team",
  "customer_contact",
  "asset_reference",
  "ioc_reference",
]);
