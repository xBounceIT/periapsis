import { Button } from "@periapsis/ui/components/ui/button";
import { Input } from "@periapsis/ui/components/ui/input";
import { Label } from "@periapsis/ui/components/ui/label";
import { Textarea } from "@periapsis/ui/components/ui/textarea";
import type {
  DfirAlertTaskSpec,
  DfirAlertTimelineEventSpec,
  DfirAssetSpec,
  DfirBoundedDocument,
  DfirEntityKind,
  DfirEntityReference,
  DfirIndicatorSpec,
  DfirTaskPriority,
  DfirTaskSpec,
  DfirTimelineEventSpec,
} from "@periapsis/contracts";
import {
  useForm,
  type FieldErrors,
  type UseFormRegister,
  type UseFormWatch,
} from "react-hook-form";
import { z } from "zod";

import { isCanonicalUuidV7 } from "../lib/uuid-v7";
import type { DfirPanel } from "./model";
import { singlePutMaximumBytes } from "./upload-request";
// oxlint-disable-next-line import/no-unassigned-import -- Vite extracts this component-owned stylesheet.
import "./resource-form.css";

const stableKey = z
  .string()
  .trim()
  .min(1)
  .max(64)
  .regex(/^[a-z][a-z0-9_.-]*$/u, "Use a lowercase stable key.");
const requiredText = (maximum: number) =>
  z.string().trim().min(1, "This field is required.").max(maximum);
const optionalText = (maximum: number) =>
  z.string().trim().max(maximum).optional().or(z.literal(""));
const optionalInstant = optionalText(64).refine(
  (value) => !value || Number.isFinite(Date.parse(value)),
  "Use a valid date and time.",
);
const requiredInstant = requiredText(64).refine(
  (value) => Number.isFinite(Date.parse(value)),
  "Use a valid date and time.",
);
const optionalUuidV7 = optionalText(36).refine(
  (value) => !value || isCanonicalUuidV7(value),
  "Use a canonical UUIDv7.",
);
const uuidV7 = requiredText(36).refine(
  (value) => isCanonicalUuidV7(value),
  "Use a canonical UUIDv7.",
);
const identifierList = optionalText(10_000).superRefine((value, context) => {
  const identifiers = splitList(value);
  if (identifiers.length > 256) {
    context.addIssue({
      code: "custom",
      message: "Use at most 256 UUIDv7 values.",
    });
    return;
  }
  if (identifiers.some((identifier) => !isCanonicalUuidV7(identifier))) {
    context.addIssue({
      code: "custom",
      message: "Every identifier must be a canonical UUIDv7.",
    });
  }
});
const tagList = optionalText(16_640).superRefine((value, context) => {
  const tags = canonicalList(value);
  if (tags.length > 256) {
    context.addIssue({
      code: "custom",
      message: "Use at most 256 unique tags.",
    });
    return;
  }
  if (tags.some((tag) => !/^[a-z][a-z0-9_.:-]{0,63}$/u.test(tag))) {
    context.addIssue({
      code: "custom",
      message: "Use lowercase stable tags of at most 64 characters.",
    });
  }
});
const addressList = optionalText(33_280).superRefine((value, context) => {
  const addresses = splitAddresses(value ?? "");
  if (addresses.ip.length > 256 || addresses.mac.length > 256) {
    context.addIssue({
      code: "custom",
      message: "Use at most 256 IP and 256 MAC addresses.",
    });
    return;
  }
  if (addresses.ip.some((address) => address.length > 45)) {
    context.addIssue({
      code: "custom",
      message: "IP address values must contain at most 45 characters.",
    });
  }
  if (addresses.mac.some((address) => address.length > 64)) {
    context.addIssue({
      code: "custom",
      message: "MAC address values must contain at most 64 characters.",
    });
  }
});
const checklistText = optionalText(51_300).superRefine((value, context) => {
  const titles = splitLines(value);
  if (titles.length > 100) {
    context.addIssue({
      code: "custom",
      message: "Use at most 100 checklist items.",
    });
    return;
  }
  if (titles.some((title) => title.length > 512)) {
    context.addIssue({
      code: "custom",
      message: "Checklist titles must contain at most 512 characters.",
    });
  }
});
const documentText = z
  .string()
  .trim()
  .max(262_144)
  .optional()
  .or(z.literal(""))
  .transform((value, context): DfirBoundedDocument | undefined => {
    if (!value) return undefined;
    try {
      const parsed: unknown = JSON.parse(value);
      if (!isBoundedDocument(parsed)) throw new TypeError("not bounded");
      return parsed;
    } catch {
      context.addIssue({
        code: "custom",
        message: "Use a JSON object within the 64 KiB document limit.",
      });
      return z.NEVER;
    }
  });
const taskPriorities = [
  "low",
  "medium",
  "high",
  "urgent",
] as const satisfies readonly DfirTaskPriority[];
const entityKinds = [
  "alert",
  "case",
  "ioc",
  "asset",
  "evidence",
  "task",
  "attachment",
  "external",
] as const satisfies readonly DfirEntityKind[];

const iocSchema = z
  .object({
    panel: z.literal("iocs"),
    type: z.enum([
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
    ]),
    value: requiredText(8_192),
    description: optionalText(16_384),
    source: requiredText(512),
    confidence: z.coerce.number().int().min(0).max(100),
    tlp: z.enum(["red", "amber", "green", "clear"]),
    firstSeen: optionalInstant,
    lastSeen: optionalInstant,
    malicious: z.enum(["unknown", "benign", "suspicious", "confirmed"]),
    tags: tagList,
    enrichment: documentText,
  })
  .superRefine((value, context) =>
    validateInstantOrder(
      value.firstSeen,
      value.lastSeen,
      context,
      "lastSeen",
      "Last seen cannot be earlier than first seen.",
    ),
  );
const assetSchema = z
  .object({
    panel: z.literal("assets"),
    hostname: optionalText(253),
    fqdn: optionalText(253),
    addresses: addressList,
    assetType: stableKey,
    operatingSystem: optionalText(512),
    owner: optionalText(512),
    businessUnit: optionalText(512),
    criticality: z.enum(["low", "medium", "high", "critical"]),
    environment: stableKey,
    externalId: optionalText(512),
    tags: tagList,
    firstSeen: optionalInstant,
    lastSeen: optionalInstant,
    customAttributes: documentText,
  })
  .refine((value) => Boolean(value.hostname || value.fqdn || value.addresses), {
    path: ["hostname"],
    message: "Record a hostname, FQDN, or network address.",
  })
  .superRefine((value, context) =>
    validateInstantOrder(
      value.firstSeen,
      value.lastSeen,
      context,
      "lastSeen",
      "Last seen cannot be earlier than first seen.",
    ),
  );
const evidenceSchema = z
  .object({
    panel: z.literal("evidence"),
    title: requiredText(512),
    description: optionalText(16_384),
    evidenceType: stableKey,
    classification: z.enum([
      "public",
      "internal",
      "confidential",
      "restricted",
    ]),
    source: requiredText(512),
    collectedAt: requiredInstant,
    retentionUntil: optionalInstant,
    legalHold: z.boolean().default(false),
    file: fileValue(),
  })
  .superRefine((value, context) =>
    validateInstantOrder(
      value.collectedAt,
      value.retentionUntil,
      context,
      "retentionUntil",
      "Retention cannot end before evidence collection.",
    ),
  );
const timelineSchema = z.object({
  panel: z.literal("timeline"),
  eventTime: requiredInstant,
  originalTimezone: requiredText(128),
  precision: z.enum([
    "year",
    "month",
    "day",
    "hour",
    "minute",
    "second",
    "millisecond",
    "microsecond",
  ]),
  source: requiredText(512),
  category: stableKey,
  title: requiredText(512),
  description: optionalText(16_384),
  actorId: optionalUuidV7,
  iocIds: identifierList,
  assetIds: identifierList,
  evidenceIds: identifierList,
  tags: tagList,
});
const taskSchema = z
  .object({
    panel: z.literal("tasks"),
    title: requiredText(512),
    description: optionalText(16_384),
    priority: z.enum(taskPriorities),
    operatorTeamId: optionalUuidV7,
    assigneeId: optionalUuidV7,
    dueAt: optionalInstant,
    checklist: checklistText,
    slaInstanceId: optionalUuidV7,
  })
  .superRefine((value, context) => {
    if (value.assigneeId && !value.operatorTeamId) {
      context.addIssue({
        code: "custom",
        path: ["operatorTeamId"],
        message: "Select an operator team before assigning an operator.",
      });
    }
  });
const attachmentSchema = z.object({
  panel: z.literal("attachments"),
  visibility: z.enum(["public", "private"]),
  classification: z.enum(["public", "internal", "confidential", "restricted"]),
  file: fileValue(),
});
const relationshipSchema = z
  .object({
    panel: z.literal("relationships"),
    sourceKind: z.enum(entityKinds),
    sourceId: optionalUuidV7,
    sourceExternalType: optionalText(64),
    sourceExternalId: optionalText(512),
    relationshipType: stableKey,
    targetKind: z.enum(entityKinds),
    targetId: optionalUuidV7,
    targetExternalType: optionalText(64),
    targetExternalId: optionalText(512),
    metadata: documentText,
  })
  .superRefine((value, context) => {
    validateReference(value, "source", context);
    validateReference(value, "target", context);
    if (sameDraftReference(value)) {
      context.addIssue({
        code: "custom",
        path: [
          value.targetKind === "external" ? "targetExternalId" : "targetId",
        ],
        message: "A resource cannot relate to itself.",
      });
    }
  });

const schemas = {
  iocs: iocSchema,
  assets: assetSchema,
  evidence: evidenceSchema,
  timeline: timelineSchema,
  tasks: taskSchema,
  attachments: attachmentSchema,
  relationships: relationshipSchema,
} as const;

export type DfirMutationDraft =
  | z.infer<typeof iocSchema>
  | z.infer<typeof assetSchema>
  | z.infer<typeof evidenceSchema>
  | z.infer<typeof timelineSchema>
  | z.infer<typeof taskSchema>
  | z.infer<typeof attachmentSchema>
  | z.infer<typeof relationshipSchema>;

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

function Fields({
  panel,
  register,
  errors,
  watch,
}: {
  panel: DfirPanel;
  register: UseFormRegister<FormValues>;
  errors: FieldErrors<FormValues>;
  watch: UseFormWatch<FormValues>;
}) {
  switch (panel) {
    case "iocs":
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
    case "assets":
      return (
        <>
          <TextField
            name="hostname"
            label="Hostname"
            register={register}
            errors={errors}
          />
          <TextField
            name="fqdn"
            label="FQDN"
            register={register}
            errors={errors}
          />
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
    case "evidence":
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
    case "timeline":
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
    case "tasks":
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
    case "attachments":
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
    case "relationships": {
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
    default:
      return null;
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

function fileValue() {
  return z.preprocess(
    (value) => {
      if (typeof FileList !== "undefined" && value instanceof FileList) {
        return value.item(0);
      }
      if (Array.isArray(value)) return value[0];
      return value;
    },
    z.custom<File>(
      (value) => typeof File !== "undefined" && value instanceof File,
      "Select a file.",
    ),
  );
}

type IndicatorDraft = Extract<DfirMutationDraft, { panel: "iocs" }>;
type AssetDraft = Extract<DfirMutationDraft, { panel: "assets" }>;
type TimelineDraft = Extract<DfirMutationDraft, { panel: "timeline" }>;
type TaskDraft = Extract<DfirMutationDraft, { panel: "tasks" }>;
type DfirSubjectKind = "alert" | "case";
type RelationshipDraft = Extract<DfirMutationDraft, { panel: "relationships" }>;

export function indicatorSpecFromDraft(
  draft: IndicatorDraft,
  fallbackInstant: string,
): DfirIndicatorSpec {
  const firstSeen = formInstant(
    draft.firstSeen || draft.lastSeen || fallbackInstant,
  );
  const lastSeen = formInstant(
    draft.lastSeen || draft.firstSeen || fallbackInstant,
  );
  return {
    confidence: draft.confidence,
    description: draft.description ?? "",
    firstSeen,
    lastSeen,
    malicious: draft.malicious,
    source: draft.source,
    tags: canonicalList(draft.tags),
    tlp: draft.tlp,
    type: draft.type,
    value: draft.value,
    ...(draft.enrichment === undefined ? {} : { enrichment: draft.enrichment }),
  };
}

export function assetSpecFromDraft(
  draft: AssetDraft,
  fallbackInstant: string,
): DfirAssetSpec {
  const addresses = splitAddresses(draft.addresses ?? "");
  const firstSeen = formInstant(
    draft.firstSeen || draft.lastSeen || fallbackInstant,
  );
  const lastSeen = formInstant(
    draft.lastSeen || draft.firstSeen || fallbackInstant,
  );
  return {
    assetType: draft.assetType,
    businessUnit: draft.businessUnit ?? "",
    criticality: draft.criticality,
    environment: draft.environment,
    externalId: draft.externalId ?? "",
    firstSeen,
    fqdn: draft.fqdn ?? "",
    hostname: draft.hostname ?? "",
    ipAddresses: addresses.ip,
    lastSeen,
    macAddresses: addresses.mac,
    operatingSystem: draft.operatingSystem ?? "",
    owner: draft.owner ?? "",
    tags: canonicalList(draft.tags),
    ...(draft.customAttributes === undefined
      ? {}
      : { customAttributes: draft.customAttributes }),
  };
}

export function timelineSpecFromDraft(
  draft: TimelineDraft,
  _subjectKind: DfirSubjectKind,
): DfirTimelineEventSpec | DfirAlertTimelineEventSpec {
  return {
    ...(draft.actorId ? { actorId: draft.actorId } : {}),
    assetIds: canonicalList(draft.assetIds),
    category: draft.category,
    description: draft.description ?? "",
    eventTime: formInstant(draft.eventTime),
    evidenceIds: canonicalList(draft.evidenceIds),
    iocIds: canonicalList(draft.iocIds),
    originalTimezone: draft.originalTimezone,
    precision: draft.precision,
    source: draft.source,
    tags: canonicalList(draft.tags),
    title: draft.title,
  };
}

export function taskSpecFromDraft(
  draft: TaskDraft,
  checklistItemIds: readonly string[],
): DfirTaskSpec {
  const checklist = splitLines(draft.checklist);
  if (checklist.length > checklistItemIds.length) {
    throw new TypeError(
      "Checklist identifiers are unavailable for this intent.",
    );
  }
  return {
    ...(draft.assigneeId ? { assigneeId: draft.assigneeId } : {}),
    checklist: checklist.map((title, index) => ({
      completed: false,
      id: checklistItemIds[index]!,
      title,
    })),
    description: draft.description ?? "",
    ...(draft.dueAt ? { dueAt: formInstant(draft.dueAt) } : {}),
    ...(draft.operatorTeamId ? { operatorTeamId: draft.operatorTeamId } : {}),
    priority: draft.priority,
    ...(draft.slaInstanceId ? { slaInstanceId: draft.slaInstanceId } : {}),
    title: draft.title,
  };
}

export function alertTaskSpecFromDraft(
  draft: TaskDraft,
  checklistItemIds: readonly string[],
): DfirAlertTaskSpec {
  const task = taskSpecFromDraft(draft, checklistItemIds);
  return {
    ...(task.assigneeId ? { assigneeId: task.assigneeId } : {}),
    checklist: task.checklist.map(({ completed, id, title }) => ({
      completed,
      id,
      title,
    })),
    description: task.description,
    ...(task.dueAt ? { dueAt: task.dueAt } : {}),
    ...(task.operatorTeamId ? { operatorTeamId: task.operatorTeamId } : {}),
    priority: task.priority,
    ...(task.slaInstanceId ? { slaInstanceId: task.slaInstanceId } : {}),
    title: task.title,
  };
}

export function relationshipReferenceFromDraft(
  draft: RelationshipDraft,
  side: "source" | "target",
): DfirEntityReference {
  const kind = draft[`${side}Kind`];
  if (kind === "external") {
    return {
      externalId: draft[`${side}ExternalId`] ?? "",
      externalType: draft[`${side}ExternalType`] ?? "",
      kind,
    };
  }
  return { id: draft[`${side}Id`] ?? "", kind };
}

export function canonicalList(value: string | undefined): string[] {
  return [...new Set(splitList(value))].toSorted(codePointCompare);
}

export function formInstant(value: string): string {
  const instant = new Date(value);
  if (!Number.isFinite(instant.valueOf())) {
    throw new TypeError("A valid investigation timestamp is required.");
  }
  const normalized = instant.toISOString();
  const fraction = instantFraction(value);
  return fraction ? `${normalized.slice(0, 19)}.${fraction}Z` : normalized;
}

export function instantInputValue(value: string): string {
  const instant = new Date(value);
  if (!Number.isFinite(instant.valueOf())) return "";
  const local = new Date(
    instant.valueOf() - instant.getTimezoneOffset() * 60_000,
  );
  const base = local.toISOString().slice(0, 19);
  const fraction = instantFraction(value);
  return fraction ? `${base}.${fraction}` : base;
}

export function documentInputValue(
  value: DfirBoundedDocument | undefined,
): string {
  return value === undefined ? "" : JSON.stringify(value, undefined, 2);
}

export function parseOptionalDocumentText(
  value: string,
): DfirBoundedDocument | undefined {
  const result = documentText.safeParse(value);
  if (!result.success) {
    throw new TypeError(
      result.error.issues[0]?.message ?? "Use a valid JSON object.",
    );
  }
  return result.data;
}

function splitList(value: string | undefined): string[] {
  return (value ?? "")
    .split(/[\s,]+/u)
    .map((item) => item.trim())
    .filter(Boolean);
}

function instantFraction(value: string): string | undefined {
  return /\.(?<fraction>\d+)(?:Z|[+-]\d{2}:\d{2})?$/u.exec(value)?.groups?.[
    "fraction"
  ];
}

function splitLines(value: string | undefined): string[] {
  return (value ?? "")
    .split(/\r?\n/u)
    .map((item) => item.trim())
    .filter(Boolean);
}

function splitAddresses(value: string): { ip: string[]; mac: string[] } {
  const ip: string[] = [];
  const mac: string[] = [];
  for (const address of canonicalList(value)) {
    if (/^(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}$/iu.test(address))
      mac.push(address);
    else ip.push(address);
  }
  return { ip, mac };
}

function codePointCompare(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function isBoundedDocument(value: unknown): value is DfirBoundedDocument {
  if (!isRecord(value)) return false;
  const count = { values: 0 };
  if (!visitDocumentValue(value, 1, count)) return false;
  return new TextEncoder().encode(JSON.stringify(value)).byteLength <= 65_536;
}

function visitDocumentValue(
  value: unknown,
  depth: number,
  count: { values: number },
): boolean {
  count.values += 1;
  if (depth > 32 || count.values > 4_096) return false;
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean"
  ) {
    return true;
  }
  if (typeof value === "number") return Number.isFinite(value);
  if (Array.isArray(value)) {
    return (
      value.length <= 4_096 &&
      value.every((item) => visitDocumentValue(item, depth + 1, count))
    );
  }
  if (!isRecord(value) || Object.keys(value).length > 200) return false;
  return Object.entries(value).every(
    ([key, item]) =>
      key.length >= 1 &&
      key.length <= 512 &&
      !hasControlCharacter(key) &&
      visitDocumentValue(item, depth + 1, count),
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasControlCharacter(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit <= 0x1f || codeUnit === 0x7f) return true;
  }
  return false;
}

function validateInstantOrder(
  first: string | undefined,
  last: string | undefined,
  context: z.RefinementCtx,
  path: string,
  message: string,
): void {
  if (first && last && Date.parse(last) < Date.parse(first)) {
    context.addIssue({
      code: "custom",
      path: [path],
      message,
    });
  }
}

function validateReference(
  value: z.infer<typeof relationshipSchema>,
  side: "source" | "target",
  context: z.RefinementCtx,
): void {
  const kind = value[`${side}Kind`];
  if (kind === "external") {
    if (!stableKey.safeParse(value[`${side}ExternalType`]).success) {
      context.addIssue({
        code: "custom",
        path: [`${side}ExternalType`],
        message: "Use a lowercase stable external type.",
      });
    }
    if (!value[`${side}ExternalId`]) {
      context.addIssue({
        code: "custom",
        path: [`${side}ExternalId`],
        message: "An external identifier is required.",
      });
    }
    return;
  }
  if (!uuidV7.safeParse(value[`${side}Id`]).success) {
    context.addIssue({
      code: "custom",
      path: [`${side}Id`],
      message: "A canonical UUIDv7 is required.",
    });
  }
}

function sameDraftReference(
  value: z.infer<typeof relationshipSchema>,
): boolean {
  if (value.sourceKind !== value.targetKind) return false;
  return value.sourceKind === "external"
    ? value.sourceExternalType === value.targetExternalType &&
        value.sourceExternalId === value.targetExternalId &&
        Boolean(value.sourceExternalType && value.sourceExternalId)
    : value.sourceId === value.targetId && Boolean(value.sourceId);
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
