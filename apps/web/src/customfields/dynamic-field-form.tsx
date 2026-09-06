import { Badge } from "@periapsis/ui/components/ui/badge";
import { Checkbox } from "@periapsis/ui/components/ui/checkbox";
import { Input } from "@periapsis/ui/components/ui/input";
import { Label } from "@periapsis/ui/components/ui/label";
import { Textarea } from "@periapsis/ui/components/ui/textarea";

import {
  canEditDefinition,
  draftText,
  presentDraft,
  visibleDefinitions,
  type CustomFieldAudience,
  type CustomFieldDefinitionView,
  type CustomFieldDraft,
  type CustomFieldDrafts,
  type CustomFieldWritePhase,
} from "./model";
// oxlint-disable-next-line import/no-unassigned-import -- Vite extracts this component-owned stylesheet.
import "./dynamic-field-form.css";

export interface DynamicFieldFormProps {
  definitions: readonly CustomFieldDefinitionView[];
  drafts: CustomFieldDrafts;
  baselineDrafts?: CustomFieldDrafts;
  audience: CustomFieldAudience;
  phase: CustomFieldWritePhase;
  errors?: Readonly<Record<string, string>>;
  disabled?: boolean;
  onChange: (key: string, draft: CustomFieldDraft) => void;
}

export function DynamicFieldForm({
  definitions,
  drafts,
  baselineDrafts = {},
  audience,
  phase,
  errors = {},
  disabled = false,
  onChange,
}: DynamicFieldFormProps) {
  const visible = visibleDefinitions(definitions, audience, phase);
  if (visible.length === 0) {
    return (
      <p className="custom-field-empty" role="status">
        No custom fields apply to this form.
      </p>
    );
  }

  return (
    <fieldset className="custom-field-grid" disabled={disabled}>
      <legend>Additional information</legend>
      {visible.map((definition) => {
        const editable = canEditDefinition(definition, audience, phase);
        const draft = drafts[definition.key] ?? { presence: "missing" };
        const error = errors[definition.key];
        const inputId = `custom-field-${definition.id}`;
        const errorId = `${inputId}-error`;
        const descriptionId = `${inputId}-description`;
        return (
          <section
            className="custom-field"
            key={definition.id}
            data-readonly={!editable || undefined}
          >
            <div className="custom-field__heading">
              <Label htmlFor={inputId}>{definition.label}</Label>
              <div
                className="custom-field__badges"
                aria-label="Field requirements"
              >
                {phase === "create" && definition.required ? (
                  <Badge variant="secondary">Required</Badge>
                ) : null}
                {!editable ? <Badge variant="outline">Read only</Badge> : null}
              </div>
            </div>
            {definition.description ? (
              <p id={descriptionId} className="custom-field__description">
                {definition.description}
              </p>
            ) : null}
            <FieldControl
              definition={definition}
              draft={draft}
              id={inputId}
              disabled={!editable}
              describedBy={[
                definition.description ? descriptionId : "",
                error ? errorId : "",
              ]
                .filter(Boolean)
                .join(" ")}
              invalid={Boolean(error)}
              onChange={(next) => onChange(definition.key, next)}
            />
            {phase === "update" && editable ? (
              <label className="custom-field__presence-control">
                <Checkbox
                  aria-label={`Store a value for ${definition.label}`}
                  checked={draft.presence !== "missing"}
                  onCheckedChange={(checked) =>
                    onChange(
                      definition.key,
                      checked === true
                        ? restorableDraft(
                            definition,
                            baselineDrafts[definition.key],
                          )
                        : { presence: "missing" },
                    )
                  }
                />
                Store a value
              </label>
            ) : null}
            {definition.nullable && editable ? (
              <label className="custom-field__null-control">
                <Checkbox
                  checked={draft.presence === "null"}
                  onCheckedChange={(checked) =>
                    onChange(
                      definition.key,
                      checked === true
                        ? { presence: "null" }
                        : { presence: "missing" },
                    )
                  }
                />
                Store an explicit empty value
              </label>
            ) : null}
            {error ? (
              <p id={errorId} className="custom-field__error" role="alert">
                {error}
              </p>
            ) : null}
          </section>
        );
      })}
    </fieldset>
  );
}

interface FieldControlProps {
  definition: CustomFieldDefinitionView;
  draft: CustomFieldDraft;
  id: string;
  disabled: boolean;
  describedBy: string;
  invalid: boolean;
  onChange: (draft: CustomFieldDraft) => void;
}

function FieldControl({
  definition,
  draft,
  id,
  disabled,
  describedBy,
  invalid,
  onChange,
}: FieldControlProps) {
  const common = {
    id,
    disabled,
    "aria-describedby": describedBy || undefined,
    "aria-invalid": invalid || undefined,
  } as const;

  if (definition.dataType === "boolean") {
    return (
      <BooleanFieldControl common={common} draft={draft} onChange={onChange} />
    );
  }
  if (
    definition.dataType === "long_text" ||
    definition.dataType === "structured_json"
  ) {
    return (
      <Textarea
        {...common}
        value={draftText(draft)}
        rows={definition.dataType === "structured_json" ? 7 : 4}
        spellCheck={definition.dataType !== "structured_json"}
        className={
          definition.dataType === "structured_json"
            ? "custom-field__code"
            : undefined
        }
        onChange={(event) =>
          onChange(
            definition.dataType === "structured_json"
              ? optionalTextDraft(event.currentTarget.value)
              : presentDraft(event.currentTarget.value),
          )
        }
      />
    );
  }
  if (definition.dataType === "single_select") {
    return (
      <select
        {...common}
        value={draftText(draft)}
        onChange={(event) =>
          onChange(optionalTextDraft(event.currentTarget.value))
        }
      >
        <option value="">Select an option</option>
        {(definition.options ?? [])
          .filter((option) => !option.archived)
          .toSorted((left, right) => left.position - right.position)
          .map((option) => (
            <option key={option.id} value={option.key}>
              {option.label}
            </option>
          ))}
      </select>
    );
  }
  if (definition.dataType === "multi_select") {
    const selected =
      draft.presence === "present" && Array.isArray(draft.value)
        ? draft.value
        : [];
    return (
      <MultiSelectFieldControl
        common={common}
        definition={definition}
        onChange={onChange}
        selected={selected}
      />
    );
  }

  const inputType = inputTypeFor(definition.dataType);
  return (
    <Input
      {...common}
      type={inputType}
      value={controlText(definition, draft)}
      min={definition.constraints?.minimum}
      max={definition.constraints?.maximum}
      minLength={definition.constraints?.minimumLength}
      maxLength={definition.constraints?.maximumLength}
      pattern={definition.constraints?.pattern}
      step={inputStepFor(definition.dataType)}
      placeholder={placeholderFor(definition.dataType)}
      onChange={(event) =>
        onChange(
          preservesEmptyString(definition.dataType)
            ? presentDraft(event.currentTarget.value)
            : optionalTextDraft(event.currentTarget.value),
        )
      }
    />
  );
}

function optionalTextDraft(value: string): CustomFieldDraft {
  return value === "" ? { presence: "missing" } : presentDraft(value);
}

function restorableDraft(
  definition: CustomFieldDefinitionView,
  baseline: CustomFieldDraft | undefined,
): CustomFieldDraft {
  if (baseline && baseline.presence !== "missing") return baseline;
  switch (definition.dataType) {
    case "boolean":
      return presentDraft(false);
    case "multi_select":
      return presentDraft([]);
    case "structured_json":
      return presentDraft("{}");
    default:
      return presentDraft("");
  }
}

function controlText(
  definition: CustomFieldDefinitionView,
  draft: CustomFieldDraft,
): string {
  const value = draftText(draft);
  if (definition.dataType !== "datetime" || !value) return value;
  const instant = new Date(value);
  if (Number.isNaN(instant.valueOf())) return value;
  const local = [
    instant.getFullYear().toString().padStart(4, "0"),
    String(instant.getMonth() + 1).padStart(2, "0"),
    String(instant.getDate()).padStart(2, "0"),
  ].join("-");
  const time = [
    String(instant.getHours()).padStart(2, "0"),
    String(instant.getMinutes()).padStart(2, "0"),
  ].join(":");
  return `${local}T${time}`;
}

function inputTypeFor(
  dataType: CustomFieldDefinitionView["dataType"],
): React.HTMLInputTypeAttribute {
  switch (dataType) {
    case "integer":
    case "decimal":
      return "number";
    case "date":
      return "date";
    case "datetime":
      return "datetime-local";
    case "email":
      return "email";
    case "url":
      return "url";
    default:
      return "text";
  }
}

function inputStepFor(
  dataType: CustomFieldDefinitionView["dataType"],
): number | "any" | undefined {
  if (dataType === "integer" || dataType === "duration") return 1;
  if (dataType === "decimal") return "any";
  return undefined;
}

function placeholderFor(
  dataType: CustomFieldDefinitionView["dataType"],
): string | undefined {
  switch (dataType) {
    case "duration":
      return "Seconds";
    case "ip":
      return "192.0.2.10 or 2001:db8::10";
    case "cidr":
      return "192.0.2.0/24 or 2001:db8::/32";
    case "user":
    case "operator_team":
    case "customer_contact":
    case "asset_reference":
    case "ioc_reference":
      return "UUIDv7";
    default:
      return undefined;
  }
}

function preservesEmptyString(
  dataType: CustomFieldDefinitionView["dataType"],
): boolean {
  return ["short_text", "long_text", "url", "email", "ip", "cidr"].includes(
    dataType,
  );
}

interface BooleanFieldControlProps {
  common: {
    readonly id: string;
    readonly disabled: boolean;
    readonly "aria-describedby": string | undefined;
    readonly "aria-invalid": true | undefined;
  };
  draft: CustomFieldDraft;
  onChange: (draft: CustomFieldDraft) => void;
}

function BooleanFieldControl({
  common,
  draft,
  onChange,
}: BooleanFieldControlProps): React.JSX.Element {
  return (
    <select
      {...common}
      value={
        draft.presence === "present"
          ? draft.value === true
            ? "true"
            : "false"
          : ""
      }
      onChange={(event) => {
        const value = event.currentTarget.value;
        onChange(
          value === ""
            ? { presence: "missing" }
            : presentDraft(value === "true"),
        );
      }}
    >
      <option value="">Not set</option>
      <option value="true">Yes</option>
      <option value="false">No</option>
    </select>
  );
}

interface MultiSelectFieldControlProps {
  common: {
    readonly id: string;
    readonly disabled: boolean;
    readonly "aria-describedby": string | undefined;
    readonly "aria-invalid": true | undefined;
  };
  definition: CustomFieldDefinitionView;
  onChange: (draft: CustomFieldDraft) => void;
  selected: any[];
}

function MultiSelectFieldControl({
  common,
  definition,
  onChange,
  selected,
}: MultiSelectFieldControlProps): React.JSX.Element {
  return (
    <select
      {...common}
      multiple
      value={selected.filter(
        (value): value is string => typeof value === "string",
      )}
      onChange={(event) =>
        onChange(
          presentDraft(
            Array.from(
              event.currentTarget.selectedOptions,
              (option) => option.value,
            ),
          ),
        )
      }
    >
      {(definition.options ?? [])
        .filter((option) => !option.archived)
        .toSorted((left, right) => left.position - right.position)
        .map((option) => (
          <option key={option.id} value={option.key}>
            {option.label}
          </option>
        ))}
    </select>
  );
}
