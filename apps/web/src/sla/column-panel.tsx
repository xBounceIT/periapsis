import { Checkbox } from "@periapsis/ui/components/ui/checkbox";
import { Input } from "@periapsis/ui/components/ui/input";
import { Textarea } from "@periapsis/ui/components/ui/textarea";
import { z } from "zod";

import { FormField } from "../components/form-field";
import { generateUuidV7 } from "../lib/uuid-v7";
import type {
  SlaColumn,
  SlaColumnCalculation,
  SlaColumnStyleRule,
  SlaColumnWrite,
} from "./model";
import { normalizeColumnWrite, parseBoundedJson } from "./model";
import type { SlaAdminApi } from "./sla-api";
import { SlaNativeSelect } from "./sla-primitives";
import type { SlaResourceEditorProps } from "./versioned-resource-panel";
import { VersionedResourcePanel } from "./versioned-resource-panel";

interface ColumnDraft {
  calculation: SlaColumnCalculation;
  customerVisible: boolean;
  filterable: boolean;
  format: SlaColumnWrite["format"];
  id: string;
  key: string;
  keyLocked: boolean;
  label: string;
  metricDefinitionId: string;
  position: string;
  sortable: boolean;
  styleRulesJson: string;
  visibleRoleKeys: string;
}

const calculations = [
  "due_at",
  "remaining_seconds",
  "consumed_percentage",
  "state",
  "breached_at",
] as const;
const formats = ["datetime", "duration", "percentage", "state_badge"] as const;

export function ColumnPanel({
  api,
  canManage,
  csrfToken,
  tenantId,
}: {
  api: SlaAdminApi;
  canManage: boolean;
  csrfToken: string;
  tenantId: string;
}): React.JSX.Element {
  return (
    <VersionedResourcePanel<SlaColumn, ColumnDraft>
      archive={(input) => api.archiveColumn(input)}
      canManage={canManage}
      create={({ body, ...context }) =>
        api.createColumn({ ...context, body: columnWrite(body) })
      }
      csrfToken={csrfToken}
      draftFrom={columnDraft}
      editor={(props) => <ColumnEditor {...props} />}
      emptyDetail="Publish role-aware, materialized columns for Alert and Case lists without recalculating every row."
      eyebrow="Materialized list projection"
      get={(input) => api.getColumn(input)}
      kindLabel="column"
      list={(input) => api.listColumns(input)}
      normalize={normalizeColumnDraft}
      renderSummary={(column) => (
        <small>
          {compactId(column.metricDefinitionId)} · {column.calculation} ·
          position {column.position}
        </small>
      )}
      tenantId={tenantId}
      version={({ body, ...context }) =>
        api.versionColumn({ ...context, body: columnVersionWrite(body) })
      }
    />
  );
}

function ColumnEditor({
  draft,
  disabled,
  setDraft,
}: SlaResourceEditorProps<ColumnDraft>): React.JSX.Element {
  return (
    <div className="sla-form-grid">
      <FormField htmlFor="sla-column-key" label="Stable key">
        <Input
          id="sla-column-key"
          required
          maxLength={64}
          disabled={disabled}
          readOnly={draft.keyLocked}
          value={draft.key}
          onChange={(event) =>
            setDraft((current) => ({ ...current, key: event.target.value }))
          }
        />
      </FormField>
      <FormField htmlFor="sla-column-label" label="Column label">
        <Input
          id="sla-column-label"
          required
          maxLength={120}
          disabled={disabled}
          value={draft.label}
          onChange={(event) =>
            setDraft((current) => ({ ...current, label: event.target.value }))
          }
        />
      </FormField>
      <FormField
        htmlFor="sla-column-metric"
        label="Source metric definition UUIDv7"
      >
        <Input
          id="sla-column-metric"
          required
          maxLength={64}
          disabled={disabled}
          value={draft.metricDefinitionId}
          onChange={(event) =>
            setDraft((current) => ({
              ...current,
              metricDefinitionId: event.target.value,
            }))
          }
        />
      </FormField>
      <FormField htmlFor="sla-column-position" label="Table position">
        <Input
          id="sla-column-position"
          required
          type="number"
          min={0}
          max={255}
          disabled={disabled}
          value={draft.position}
          onChange={(event) =>
            setDraft((current) => ({
              ...current,
              position: event.target.value,
            }))
          }
        />
      </FormField>
      <SlaNativeSelect
        disabled={disabled}
        id="sla-column-calculation"
        label="Calculation"
        options={calculations}
        value={draft.calculation}
        onChange={(calculation) =>
          setDraft((current) => ({ ...current, calculation }))
        }
      />
      <SlaNativeSelect
        disabled={disabled}
        id="sla-column-format"
        label="Display format"
        options={formats}
        value={draft.format}
        onChange={(format) => setDraft((current) => ({ ...current, format }))}
      />
      <div className="sla-form-grid__wide">
        <FormField
          htmlFor="sla-column-roles"
          label="Visible role keys"
          optional
          hint="Comma-separated exact tenant role keys. Empty means no role-specific allowlist."
        >
          <Input
            id="sla-column-roles"
            disabled={disabled}
            value={draft.visibleRoleKeys}
            onChange={(event) =>
              setDraft((current) => ({
                ...current,
                visibleRoleKeys: event.target.value,
              }))
            }
          />
        </FormField>
      </div>
      <div className="sla-form-grid__wide">
        <FormField
          htmlFor="sla-column-style-rules"
          label="Ordered style rules"
          hint="First matching state/percentage/remaining rule supplies a stable style key."
        >
          <Textarea
            id="sla-column-style-rules"
            rows={9}
            spellCheck={false}
            disabled={disabled}
            value={draft.styleRulesJson}
            onChange={(event) =>
              setDraft((current) => ({
                ...current,
                styleRulesJson: event.target.value,
              }))
            }
          />
        </FormField>
      </div>
      <label className="sla-checkline">
        <Checkbox
          disabled={disabled}
          checked={draft.sortable}
          onCheckedChange={(checked) =>
            setDraft((current) => ({ ...current, sortable: checked === true }))
          }
        />
        <span>Materialize a server-sortable value</span>
      </label>
      <label className="sla-checkline">
        <Checkbox
          disabled={disabled}
          checked={draft.filterable}
          onCheckedChange={(checked) =>
            setDraft((current) => ({
              ...current,
              filterable: checked === true,
            }))
          }
        />
        <span>Materialize a server-filterable value</span>
      </label>
      <label className="sla-checkline">
        <Checkbox
          disabled={disabled}
          checked={draft.customerVisible}
          onCheckedChange={(checked) =>
            setDraft((current) => ({
              ...current,
              customerVisible: checked === true,
            }))
          }
        />
        <span>Expose this column in customer-safe ticket projections</span>
      </label>
    </div>
  );
}

function columnDraft(column?: SlaColumn): ColumnDraft {
  return {
    id: column?.id ?? generateUuidV7(),
    key: column?.key ?? "",
    keyLocked: column !== undefined,
    label: column?.label ?? "",
    metricDefinitionId: column?.metricDefinitionId ?? "",
    calculation: column?.calculation ?? "remaining_seconds",
    format: column?.format ?? "duration",
    position: String(column?.position ?? 100),
    sortable: column?.sortable ?? true,
    filterable: column?.filterable ?? true,
    customerVisible: column?.customerVisible ?? false,
    visibleRoleKeys: column?.visibleRoleKeys.join(", ") ?? "",
    styleRulesJson: JSON.stringify(column?.styleRules ?? [], null, 2),
  };
}

function normalizeColumnDraft(draft: ColumnDraft): ColumnDraft {
  const value = normalizeColumnWrite(columnWrite(draft));
  return {
    ...draft,
    key: value.key,
    label: value.label,
    metricDefinitionId: value.metricDefinitionId,
    position: String(value.position),
    sortable: value.sortable,
    filterable: value.filterable,
    customerVisible: value.customerVisible,
    visibleRoleKeys: value.visibleRoleKeys.join(", "),
    styleRulesJson: JSON.stringify(value.styleRules, null, 2),
  };
}

function columnWrite(draft: ColumnDraft): SlaColumnWrite {
  return normalizeColumnWrite({
    id: draft.id,
    key: draft.key,
    label: draft.label,
    metricDefinitionId: draft.metricDefinitionId,
    calculation: draft.calculation,
    format: draft.format,
    sortable: draft.sortable,
    filterable: draft.filterable,
    position: Number(draft.position),
    customerVisible: draft.customerVisible,
    visibleRoleKeys: draft.visibleRoleKeys
      .split(",")
      .map((value) => value.trim())
      .filter(Boolean),
    styleRules: parseBoundedJson(
      draft.styleRulesJson,
      "Column style rules",
      (value) => styleRulesSchema.parse(value),
    ),
  });
}

function columnVersionWrite(draft: ColumnDraft): Omit<SlaColumnWrite, "id"> {
  const value = columnWrite(draft);
  return {
    key: value.key,
    label: value.label,
    metricDefinitionId: value.metricDefinitionId,
    calculation: value.calculation,
    format: value.format,
    sortable: value.sortable,
    filterable: value.filterable,
    position: value.position,
    customerVisible: value.customerVisible,
    visibleRoleKeys: value.visibleRoleKeys,
    styleRules: value.styleRules,
  };
}

function compactId(value: string): string {
  return value.length > 16 ? `${value.slice(0, 8)}…${value.slice(-5)}` : value;
}

const styleRulesSchema: z.ZodType<SlaColumnStyleRule[]> = z.array(
  z.strictObject({
    styleKey: z.string(),
    state: z
      .enum([
        "pending",
        "on_track",
        "at_risk",
        "paused",
        "breached",
        "completed",
      ])
      .optional(),
    minimumPercentage: z.number().finite().optional(),
    maximumRemainingMicros: z.number().finite().optional(),
  }),
);
