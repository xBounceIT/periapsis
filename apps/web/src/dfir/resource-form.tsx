import { Button } from "@periapsis/ui/components/ui/button";
import { Input } from "@periapsis/ui/components/ui/input";
import { Label } from "@periapsis/ui/components/ui/label";
import { Textarea } from "@periapsis/ui/components/ui/textarea";
import {
  useForm,
  type FieldErrors,
  type UseFormRegister,
  type UseFormWatch,
} from "react-hook-form";
import {
  assetSchema,
  attachmentSchema,
  entityKinds,
  evidenceSchema,
  iocSchema,
  relationshipSchema,
  taskPriorities,
  taskSchema,
  timelineSchema,
  type DfirMutationDraft,
  type DfirSubjectKind,
} from "./resource-form-model";

import type { DfirPanel } from "./model";
import { singlePutMaximumBytes } from "./upload-request";
// oxlint-disable-next-line import/no-unassigned-import -- Vite extracts this component-owned stylesheet.
import "./resource-form.css";

const schemas = {
  iocs: iocSchema,
  assets: assetSchema,
  evidence: evidenceSchema,
  timeline: timelineSchema,
  tasks: taskSchema,
  attachments: attachmentSchema,
  relationships: relationshipSchema,
} as const;

type FormValues = Record<string, unknown>;

export interface DfirResourceFormProps {
  panel: DfirPanel;
  subjectKind: DfirSubjectKind;
  mode?: "create" | "replace";
  initialValues?: FormValues;
  maximumUploadBytes?: number;
  busy?: boolean;
  onCancel: () => void;
  onSubmit: (draft: DfirMutationDraft) => void | Promise<void>;
}

export function DfirResourceForm({
  panel,
  mode = "create",
  initialValues,
  maximumUploadBytes = singlePutMaximumBytes,
  busy = false,
  onCancel,
  onSubmit,
}: DfirResourceFormProps) {
  const {
    register,
    handleSubmit,
    setError,
    watch,
    formState: { errors },
  } = useForm<FormValues>({
    defaultValues: { ...defaultsFor(panel), ...initialValues },
    shouldUnregister: true,
  });

  return (
    <form
      className="dfir-resource-form"
      noValidate
      onSubmit={handleSubmit(async (values) => {
        const result = schemas[panel].safeParse({ ...values, panel });
        if (!result.success) {
          for (const issue of result.error.issues) {
            const field = issue.path[0];
            if (typeof field === "string")
              setError(field, { type: "validate", message: issue.message });
          }
          return;
        }
        if (
          "file" in result.data &&
          result.data.file.size > maximumUploadBytes
        ) {
          setError("file", {
            type: "max",
            message: "The selected file exceeds this tenant's upload limit.",
          });
          return;
        }
        await onSubmit(result.data);
      })}
    >
      <fieldset disabled={busy}>
        <legend>{formTitle(panel, mode)}</legend>
        <Fields
          panel={panel}
          register={register}
          errors={errors}
          watch={watch}
        />
        <div className="dfir-resource-form__actions">
          <Button type="button" variant="outline" onClick={onCancel}>
            Cancel
          </Button>
          <Button type="submit">
            {busy ? "Saving…" : submitLabel(panel, mode)}
          </Button>
        </div>
      </fieldset>
    </form>
  );
}

interface FieldsProps {
  panel: DfirPanel;
  register: UseFormRegister<FormValues>;
  errors: FieldErrors<FormValues>;
  watch: UseFormWatch<FormValues>;
}
function Fields({ panel, register, errors, watch }: FieldsProps) {
  switch (panel) {
    case "iocs":
      return <IndicatorFields register={register} errors={errors} />;
    case "assets":
      return <AssetFields register={register} errors={errors} />;
    case "evidence":
      return <EvidenceFields register={register} errors={errors} />;
    case "timeline":
      return <TimelineFields register={register} errors={errors} />;
    case "tasks":
      return <TaskFields register={register} errors={errors} />;
    case "attachments":
      return <AttachmentFields register={register} errors={errors} />;
    case "relationships":
      return (
        <RelationshipFields register={register} errors={errors} watch={watch} />
      );
    default:
      return null;
  }
}

function IndicatorFields({
  register,
  errors,
}: Pick<FieldsProps, "register" | "errors">) {
  return (
    <>
      <SelectField
        name="type"
        label="Indicator type"
        options={[
          "ipv4",
          "ipv6",
          "domain",
          "hostname",
          "url",
          "email",
          "md5",
          "sha1",
          "sha256",
          "sha512",
          "filename",
          "registry_key",
          "process",
          "mutex",
          "cve",
          "custom",
        ]}
        register={register}
        errors={errors}
      />
      <TextField
        name="value"
        label="Observable value"
        register={register}
        errors={errors}
      />
      <TextareaField
        name="description"
        label="Description"
        register={register}
        errors={errors}
      />
      <TextField
        name="source"
        label="Source"
        register={register}
        errors={errors}
      />
      <TextField
        name="confidence"
        label="Confidence"
        type="number"
        register={register}
        errors={errors}
      />
      <SelectField
        name="tlp"
        label="Traffic light protocol"
        options={["red", "amber", "green", "clear"]}
        register={register}
        errors={errors}
      />
      <SelectField
        name="malicious"
        label="Assessment"
        options={["unknown", "benign", "suspicious", "confirmed"]}
        register={register}
        errors={errors}
      />
      <TextField
        name="firstSeen"
        label="First seen"
        type="datetime-local"
        register={register}
        errors={errors}
      />
      <TextField
        name="lastSeen"
        label="Last seen"
        type="datetime-local"
        register={register}
        errors={errors}
      />
      <TextField
        name="tags"
        label="Tags, comma separated"
        register={register}
        errors={errors}
      />
      <TextareaField
        name="enrichment"
        label="Enrichment (JSON object)"
        register={register}
        errors={errors}
      />
    </>
  );
}

function AssetFields({
  register,
  errors,
}: Pick<FieldsProps, "register" | "errors">) {
  return (
    <>
      <TextField
        name="hostname"
        label="Hostname"
        register={register}
        errors={errors}
      />
      <TextField name="fqdn" label="FQDN" register={register} errors={errors} />
      <TextField
        name="addresses"
        label="IP or MAC addresses, comma separated"
        register={register}
        errors={errors}
      />
      <TextField
        name="assetType"
        label="Asset type"
        register={register}
        errors={errors}
      />
      <TextField
        name="operatingSystem"
        label="Operating system"
        register={register}
        errors={errors}
      />
      <TextField
        name="owner"
        label="Owner"
        register={register}
        errors={errors}
      />
      <TextField
        name="businessUnit"
        label="Business unit"
        register={register}
        errors={errors}
      />
      <SelectField
        name="criticality"
        label="Criticality"
        options={["low", "medium", "high", "critical"]}
        register={register}
        errors={errors}
      />
      <TextField
        name="environment"
        label="Environment"
        register={register}
        errors={errors}
      />
      <TextField
        name="externalId"
        label="External asset ID"
        register={register}
        errors={errors}
      />
      <TextField
        name="tags"
        label="Tags, comma separated"
        register={register}
        errors={errors}
      />
      <TextField
        name="firstSeen"
        label="First seen"
        type="datetime-local"
        register={register}
        errors={errors}
      />
      <TextField
        name="lastSeen"
        label="Last seen"
        type="datetime-local"
        register={register}
        errors={errors}
      />
      <TextareaField
        name="customAttributes"
        label="Custom attributes (JSON object)"
        register={register}
        errors={errors}
      />
    </>
  );
}

function EvidenceFields({
  register,
  errors,
}: Pick<FieldsProps, "register" | "errors">) {
  return (
    <>
      <TextField
        name="title"
        label="Evidence title"
        register={register}
        errors={errors}
      />
      <TextareaField
        name="description"
        label="Description"
        register={register}
        errors={errors}
      />
      <TextField
        name="evidenceType"
        label="Evidence type"
        register={register}
        errors={errors}
      />
      <SelectField
        name="classification"
        label="Classification"
        options={["public", "internal", "confidential", "restricted"]}
        register={register}
        errors={errors}
      />
      <TextField
        name="source"
        label="Collection source"
        register={register}
        errors={errors}
      />
      <TextField
        name="collectedAt"
        label="Collected at"
        type="datetime-local"
        register={register}
        errors={errors}
      />
      <TextField
        name="retentionUntil"
        label="Retain until"
        type="datetime-local"
        register={register}
        errors={errors}
      />
      <FileField register={register} errors={errors} />
      <label className="dfir-resource-form__check">
        <input type="checkbox" {...register("legalHold")} />
        Place on legal hold at collection
      </label>
    </>
  );
}

function TimelineFields({
  register,
  errors,
}: Pick<FieldsProps, "register" | "errors">) {
  return (
    <>
      <TextField
        name="eventTime"
        label="Event time"
        type="datetime-local"
        register={register}
        errors={errors}
      />
      <TextField
        name="originalTimezone"
        label="Original timezone"
        register={register}
        errors={errors}
      />
      <SelectField
        name="precision"
        label="Time precision"
        options={[
          "year",
          "month",
          "day",
          "hour",
          "minute",
          "second",
          "millisecond",
          "microsecond",
        ]}
        register={register}
        errors={errors}
      />
      <TextField
        name="source"
        label="Source"
        register={register}
        errors={errors}
      />
      <TextField
        name="category"
        label="Category"
        register={register}
        errors={errors}
      />
      <TextField
        name="title"
        label="Event title"
        register={register}
        errors={errors}
      />
      <TextareaField
        name="description"
        label="Description"
        register={register}
        errors={errors}
      />
      <TextField
        name="actorId"
        label="Actor UUIDv7"
        register={register}
        errors={errors}
      />
      <TextareaField
        name="iocIds"
        label="Linked IOC UUIDv7 values"
        register={register}
        errors={errors}
      />
      <TextareaField
        name="assetIds"
        label="Linked asset UUIDv7 values"
        register={register}
        errors={errors}
      />
      <TextareaField
        name="evidenceIds"
        label="Linked evidence UUIDv7 values"
        register={register}
        errors={errors}
      />
      <TextField
        name="tags"
        label="Tags, comma separated"
        register={register}
        errors={errors}
      />
    </>
  );
}

function TaskFields({
  register,
  errors,
}: Pick<FieldsProps, "register" | "errors">) {
  return (
    <>
      <TextField
        name="title"
        label="Task title"
        register={register}
        errors={errors}
      />
      <TextareaField
        name="description"
        label="Instructions"
        register={register}
        errors={errors}
      />
      <SelectField
        name="priority"
        label="Priority"
        options={taskPriorities}
        register={register}
        errors={errors}
      />
      <TextField
        name="operatorTeamId"
        label="Operator team UUIDv7"
        register={register}
        errors={errors}
      />
      <TextField
        name="assigneeId"
        label="Assignee UUIDv7"
        register={register}
        errors={errors}
      />
      <TextField
        name="dueAt"
        label="Due at"
        type="datetime-local"
        register={register}
        errors={errors}
      />
      <TextareaField
        name="checklist"
        label="Checklist items, one per line"
        register={register}
        errors={errors}
      />
      <TextField
        name="slaInstanceId"
        label="SLA instance UUIDv7"
        register={register}
        errors={errors}
      />
    </>
  );
}

function AttachmentFields({
  register,
  errors,
}: Pick<FieldsProps, "register" | "errors">) {
  return (
    <>
      <SelectField
        name="visibility"
        label="Visibility"
        options={["private", "public"]}
        register={register}
        errors={errors}
      />
      <SelectField
        name="classification"
        label="Classification"
        options={["public", "internal", "confidential", "restricted"]}
        register={register}
        errors={errors}
      />
      <FileField register={register} errors={errors} />
    </>
  );
}

function RelationshipFields({
  register,
  errors,
  watch,
}: Pick<FieldsProps, "register" | "errors" | "watch">) {
  {
    const sourceIsExternal = watch("sourceKind") === "external";
    const targetIsExternal = watch("targetKind") === "external";
    return (
      <>
        <SelectField
          name="sourceKind"
          label="Source type"
          options={entityKinds}
          register={register}
          errors={errors}
        />
        {sourceIsExternal ? (
          <>
            <TextField
              name="sourceExternalType"
              label="Source external type"
              register={register}
              errors={errors}
            />
            <TextField
              name="sourceExternalId"
              label="Source external ID"
              register={register}
              errors={errors}
            />
          </>
        ) : (
          <TextField
            name="sourceId"
            label="Source ID"
            register={register}
            errors={errors}
          />
        )}
        <TextField
          name="relationshipType"
          label="Relationship"
          register={register}
          errors={errors}
        />
        <SelectField
          name="targetKind"
          label="Target type"
          options={entityKinds}
          register={register}
          errors={errors}
        />
        {targetIsExternal ? (
          <>
            <TextField
              name="targetExternalType"
              label="Target external type"
              register={register}
              errors={errors}
            />
            <TextField
              name="targetExternalId"
              label="Target external ID"
              register={register}
              errors={errors}
            />
          </>
        ) : (
          <TextField
            name="targetId"
            label="Target ID"
            register={register}
            errors={errors}
          />
        )}
        <TextareaField
          name="metadata"
          label="Relationship metadata (JSON object)"
          register={register}
          errors={errors}
        />
      </>
    );
  }
}

function TextField({
  name,
  label,
  type = "text",
  register,
  errors,
}: FieldProps & { type?: React.HTMLInputTypeAttribute }) {
  const error = fieldError(errors, name);
  return (
    <div className="dfir-resource-form__field">
      <Label htmlFor={`dfir-${name}`}>{label}</Label>
      <Input
        id={`dfir-${name}`}
        type={type}
        step={type === "datetime-local" ? "0.000001" : undefined}
        aria-invalid={Boolean(error) || undefined}
        aria-describedby={error ? `dfir-${name}-error` : undefined}
        {...register(name)}
      />
      {error ? (
        <p id={`dfir-${name}-error`} role="alert">
          {error}
        </p>
      ) : null}
    </div>
  );
}

function TextareaField({ name, label, register, errors }: FieldProps) {
  const error = fieldError(errors, name);
  return (
    <div className="dfir-resource-form__field dfir-resource-form__field--wide">
      <Label htmlFor={`dfir-${name}`}>{label}</Label>
      <Textarea
        id={`dfir-${name}`}
        aria-invalid={Boolean(error) || undefined}
        aria-describedby={error ? `dfir-${name}-error` : undefined}
        {...register(name)}
      />
      {error ? (
        <p id={`dfir-${name}-error`} role="alert">
          {error}
        </p>
      ) : null}
    </div>
  );
}

function SelectField({
  name,
  label,
  options,
  register,
  errors,
}: FieldProps & { options: readonly string[] }) {
  const error = fieldError(errors, name);
  return (
    <div className="dfir-resource-form__field">
      <Label htmlFor={`dfir-${name}`}>{label}</Label>
      <select
        id={`dfir-${name}`}
        aria-invalid={Boolean(error) || undefined}
        aria-describedby={error ? `dfir-${name}-error` : undefined}
        {...register(name)}
      >
        {options.map((option) => (
          <option value={option} key={option}>
            {option.replaceAll("_", " ")}
          </option>
        ))}
      </select>
      {error ? (
        <p id={`dfir-${name}-error`} role="alert">
          {error}
        </p>
      ) : null}
    </div>
  );
}

function FileField({
  register,
  errors,
}: Pick<FieldProps, "register" | "errors">) {
  const error = fieldError(errors, "file");
  return (
    <div className="dfir-resource-form__field dfir-resource-form__field--wide">
      <Label htmlFor="dfir-file">File</Label>
      <Input
        id="dfir-file"
        type="file"
        aria-invalid={Boolean(error) || undefined}
        aria-describedby={error ? "dfir-file-error" : "dfir-file-guidance"}
        {...register("file")}
      />
      <p id="dfir-file-guidance" className="dfir-resource-form__guidance">
        The platform verifies SHA-256 and scan state before download becomes
        available.
      </p>
      {error ? (
        <p id="dfir-file-error" role="alert">
          {error}
        </p>
      ) : null}
    </div>
  );
}

interface FieldProps {
  name: string;
  label: string;
  register: UseFormRegister<FormValues>;
  errors: FieldErrors<FormValues>;
}

function fieldError(
  errors: FieldErrors<FormValues>,
  name: string,
): string | undefined {
  const message = errors[name]?.message;
  return typeof message === "string" ? message : undefined;
}

function defaultsFor(panel: DfirPanel): FormValues {
  switch (panel) {
    case "iocs":
      return {
        type: "domain",
        confidence: 50,
        tlp: "amber",
        malicious: "unknown",
      };
    case "assets":
      return {
        assetType: "endpoint",
        criticality: "medium",
        environment: "production",
      };
    case "evidence":
      return { classification: "internal", legalHold: false };
    case "timeline":
      return { precision: "second", originalTimezone: "UTC" };
    case "tasks":
      return { priority: "medium" };
    case "attachments":
      return { visibility: "private", classification: "internal" };
    case "relationships":
      return {
        sourceKind: "case",
        targetKind: "ioc",
        relationshipType: "related_to",
      };
    default:
      throw new Error("Unsupported DFIR panel");
  }
}

function formTitle(panel: DfirPanel, mode: "create" | "replace"): string {
  if (mode === "replace") {
    return panel === "iocs" ? "Edit indicator" : "Edit asset";
  }
  return {
    iocs: "Add an indicator",
    assets: "Add an asset",
    evidence: "Collect evidence",
    timeline: "Record a timeline event",
    tasks: "Create an investigation task",
    attachments: "Attach a file",
    relationships: "Link investigation resources",
  }[panel];
}

function submitLabel(panel: DfirPanel, mode: "create" | "replace"): string {
  if (mode === "replace") return "Save changes";
  return panel === "evidence"
    ? "Begin evidence collection"
    : panel === "attachments"
      ? "Prepare secure upload"
      : "Add to investigation";
}
