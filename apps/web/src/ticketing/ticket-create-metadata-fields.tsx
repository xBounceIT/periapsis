import { Input } from "@periapsis/ui/components/ui/input";
import { FormField } from "../components/form-field";
import type { TicketCreatePageState } from "./ticket-create-page";
import {
  alertSeverities,
  humanizeKey,
  ticketPriorities,
} from "./ticketing-model";
function NativeField<T extends string>({
  label,
  onChange,
  options,
  value,
}: {
  label: string;
  onChange: (value: T) => void;
  options: readonly T[];
  value: T;
}): React.JSX.Element {
  return (
    <label className="ticket-native-field">
      <span>{label}</span>
      <select
        value={value}
        onChange={(event) => {
          const selected = options.find(
            (option) => option === event.target.value,
          );
          if (selected !== undefined) onChange(selected);
        }}
      >
        {options.map((option) => (
          <option key={option} value={option}>
            {humanizeKey(option)}
          </option>
        ))}
      </select>
    </label>
  );
}
interface TicketCreateMetadataFieldsProps {
  draft: TicketCreatePageState["draft"];
  kind: TicketCreatePageState["kind"];
  setDraft: TicketCreatePageState["setDraft"];
}
export function TicketCreateMetadataFields({
  draft,
  kind,
  setDraft,
}: TicketCreateMetadataFieldsProps): React.JSX.Element {
  return (
    <div className="ticket-create-form__grid">
      <NativeField
        label="Severity"
        value={draft.severity}
        options={alertSeverities}
        onChange={(severity) =>
          setDraft((current) => ({ ...current, severity }))
        }
      />
      <NativeField
        label="Priority"
        value={draft.priority}
        options={ticketPriorities}
        onChange={(priority) =>
          setDraft((current) => ({ ...current, priority }))
        }
      />
      <FormField htmlFor="ticket-category" label="Category">
        <Input
          id="ticket-category"
          maxLength={100}
          value={draft.category}
          onChange={(event) =>
            setDraft((current) => ({
              ...current,
              category: event.target.value,
            }))
          }
        />
      </FormField>
      <FormField
        htmlFor="ticket-classification"
        label="Classification"
        optional
      >
        <Input
          id="ticket-classification"
          maxLength={100}
          value={draft.classification}
          onChange={(event) =>
            setDraft((current) => ({
              ...current,
              classification: event.target.value,
            }))
          }
        />
      </FormField>
      {kind === "alert" ? (
        <>
          <FormField htmlFor="ticket-source" label="Source">
            <Input
              id="ticket-source"
              maxLength={120}
              value={draft.source}
              onChange={(event) =>
                setDraft((current) => ({
                  ...current,
                  source: event.target.value,
                }))
              }
            />
          </FormField>
          <FormField htmlFor="ticket-source-type" label="Source type">
            <Input
              id="ticket-source-type"
              maxLength={120}
              value={draft.sourceType}
              onChange={(event) =>
                setDraft((current) => ({
                  ...current,
                  sourceType: event.target.value,
                }))
              }
            />
          </FormField>
        </>
      ) : null}
      <FormField htmlFor="ticket-workflow" label="Workflow ID" optional>
        <Input
          id="ticket-workflow"
          value={draft.workflowId}
          onChange={(event) =>
            setDraft((current) => ({
              ...current,
              workflowId: event.target.value,
            }))
          }
        />
      </FormField>
      <FormField htmlFor="ticket-team" label="Assigned team ID" optional>
        <Input
          id="ticket-team"
          value={draft.assignedTeamId}
          onChange={(event) =>
            setDraft((current) => ({
              ...current,
              assignedTeamId: event.target.value,
            }))
          }
        />
      </FormField>
    </div>
  );
}
