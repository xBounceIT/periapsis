import type {
  NotificationEventType,
  NotificationObjectType,
  NotificationRule,
  NotificationRuleWrite,
} from "@periapsis/contracts";
import { Badge } from "@periapsis/ui/components/ui/badge";
import { Button } from "@periapsis/ui/components/ui/button";
import { Input } from "@periapsis/ui/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableRow,
} from "@periapsis/ui/components/ui/table";
import { Textarea } from "@periapsis/ui/components/ui/textarea";
import { PencilLine, Plus } from "lucide-react";
import { useCallback, useRef, useState, type FormEvent } from "react";
import { TableColumnHeaders } from "../components/table-column-headers";

import { FormField } from "../components/form-field";
import { TenantInstant } from "../lib/tenant-date-time-context";
import {
  bindMutationAttempt,
  emptyRuleWrite,
  parseCondition,
  parseRecipients,
  resetMutationAttempt,
  type MutationAttemptReference,
} from "./model";
import type { NotificationAdminApi, Versioned } from "./notification-api";
import {
  EditorActions,
  InventoryHeading,
  NotificationEmpty,
  NotificationError,
  NotificationLoading,
} from "./notification-primitives";
import {
  useCursorInventory,
  type CursorInventory,
} from "./use-cursor-inventory";

const eventTypes = [
  "alert.created",
  "alert.assigned",
  "alert.claimed",
  "alert.status_changed",
  "alert.escalated",
  "alert.watcher_added",
  "alert.watcher_removed",
  "case.created",
  "case.assigned",
  "case.claimed",
  "case.transferred",
  "case.status_changed",
  "case.watcher_added",
  "case.watcher_removed",
  "comment.public_added",
  "comment.private_added",
  "contact.changed",
  "sla.warning",
  "sla.breached",
  "task.assigned",
  "evidence.added",
  "webhook.custom",
] as const satisfies readonly NotificationEventType[];
const objectTypes = [
  "alert",
  "case",
  "task",
  "evidence",
  "contact",
] as const satisfies readonly NotificationObjectType[];

interface RuleDraft {
  channel: NotificationRuleWrite["channel"];
  condition: string;
  delayMs: string;
  description: string;
  effectiveFrom: string;
  enabled: boolean;
  eventType: NotificationEventType;
  name: string;
  objectType: NotificationObjectType;
  priority: string;
  recipients: string;
  templateId: string;
  templateVersion: string;
}

interface RulesPanelProps {
  api: NotificationAdminApi;
  csrfToken: string;
  tenantId: string;
}

export function RulesPanel({
  api,
  csrfToken,
  tenantId,
}: RulesPanelProps): React.JSX.Element {
  const load = useCallback(
    (after: string | undefined, signal: AbortSignal) =>
      api.listRules({ ...(after ? { after } : {}), signal, tenantId }),
    [api, tenantId],
  );
  const inventory = useCursorInventory(load);
  const [editing, setEditing] = useState<
    Versioned<NotificationRule> | "new" | null
  >(null);
  const [draft, setDraft] = useState<RuleDraft>(() =>
    draftFromRule(emptyRuleWrite),
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const attempt = useRef<MutationAttemptReference>({ current: null });

  async function editRule(id: string): Promise<void> {
    setBusy(true);
    setError(null);
    try {
      const current = await api.getRule({ id, tenantId });
      setEditing(current);
      setDraft(draftFromRule(current.value));
      resetMutationAttempt(attempt.current);
    } catch (caught: unknown) {
      setError(caught);
    } finally {
      setBusy(false);
    }
  }

  function createRule(): void {
    setEditing("new");
    setDraft(
      draftFromRule({
        ...emptyRuleWrite,
        effectiveFrom: new Date().toISOString(),
      }),
    );
    setError(null);
    setNotice(null);
    resetMutationAttempt(attempt.current);
  }

  async function saveRule(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (!editing) return;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const body = ruleFromDraft(draft);
      const operation =
        editing === "new"
          ? "notification-rule.create"
          : "notification-rule.version";
      const idempotencyKey = bindMutationAttempt(
        attempt.current,
        operation,
        tenantId,
        body,
      );
      const saved =
        editing === "new"
          ? await api.createRule({ body, csrfToken, idempotencyKey, tenantId })
          : await api.versionRule({
              body,
              csrfToken,
              etag: editing.etag,
              id: editing.value.id,
              idempotencyKey,
              tenantId,
            });
      inventory.upsert(saved.value, (rule) => rule.id);
      setEditing(saved);
      setDraft(draftFromRule(saved.value));
      setNotice(`Rule version ${saved.value.version} is current.`);
      resetMutationAttempt(attempt.current);
    } catch (caught: unknown) {
      setError(caught);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="notification-panel-grid">
      <RuleInventory
        busy={busy}
        createRule={createRule}
        editRule={editRule}
        inventory={inventory}
      />

      <RuleEditor
        busy={busy}
        draft={draft}
        editing={editing}
        error={error}
        notice={notice}
        saveRule={saveRule}
        setDraft={setDraft}
        setEditing={setEditing}
      />
    </div>
  );
}

function draftFromRule(value: NotificationRuleWrite): RuleDraft {
  return {
    channel: value.channel,
    condition: JSON.stringify(value.condition, null, 2),
    delayMs: String(value.delayMs),
    description: value.description,
    effectiveFrom: value.effectiveFrom,
    enabled: value.enabled,
    eventType: value.eventType,
    name: value.name,
    objectType: value.objectType,
    priority: String(value.priority),
    recipients: JSON.stringify(value.recipients, null, 2),
    templateId: value.templateId,
    templateVersion: String(value.templateVersion),
  };
}

function ruleFromDraft(draft: RuleDraft): NotificationRuleWrite {
  return {
    ...emptyRuleWrite,
    name: draft.name.trim(),
    description: draft.description.trim(),
    eventType: draft.eventType,
    objectType: draft.objectType,
    channel: draft.channel,
    condition: parseCondition(draft.condition),
    recipients: parseRecipients(draft.recipients),
    templateId: draft.templateId.trim(),
    templateVersion: Number(draft.templateVersion),
    priority: Number(draft.priority),
    delayMs: Number(draft.delayMs),
    effectiveFrom: draft.effectiveFrom.trim(),
    enabled: draft.enabled,
  };
}

function NativeSelect<T extends string>({
  id,
  label,
  onChange,
  options,
  value,
}: {
  id: string;
  label: string;
  onChange: (value: T) => void;
  options: readonly T[];
  value: T;
}) {
  return (
    <FormField htmlFor={id} label={label}>
      <select
        id={id}
        value={value}
        onChange={(event) => {
          const next = options.find((option) => option === event.target.value);
          if (next !== undefined) onChange(next);
        }}
      >
        {options.map((option) => (
          <option key={option} value={option}>
            {option}
          </option>
        ))}
      </select>
    </FormField>
  );
}

interface RuleEditorProps {
  busy: boolean;
  draft: RuleDraft;
  editing: Versioned<NotificationRule> | "new" | null;
  error: unknown;
  notice: string | null;
  saveRule: (event: FormEvent<HTMLFormElement>) => Promise<void>;
  setDraft: React.Dispatch<React.SetStateAction<RuleDraft>>;
  setEditing: React.Dispatch<
    React.SetStateAction<Versioned<NotificationRule> | "new" | null>
  >;
}

function RuleEditor({
  busy,
  draft,
  editing,
  error,
  notice,
  saveRule,
  setDraft,
  setEditing,
}: RuleEditorProps): React.JSX.Element {
  return (
    <aside className="notification-editor" aria-label="Rule version editor">
      {!editing ? (
        <NotificationEmpty
          title="Select a rule"
          detail="Open a current rule to append a version, or start a new lineage."
        />
      ) : (
        <form onSubmit={(event) => void saveRule(event)}>
          <header>
            <div>
              <p className="section-label">
                {editing === "new" ? "New lineage" : `Rule ${editing.value.id}`}
              </p>
              <h2>
                {editing === "new"
                  ? "Create routing rule"
                  : `Append version ${editing.value.version + 1}`}
              </h2>
            </div>
            {editing !== "new" ? (
              <Badge variant="outline">ETag {editing.etag}</Badge>
            ) : null}
          </header>
          {error ? (
            <NotificationError
              error={error}
              fallback="The rule could not be saved."
            />
          ) : null}
          {notice ? (
            <p className="notification-notice" role="status">
              {notice}
            </p>
          ) : null}
          <div className="notification-form-grid">
            <FormField htmlFor="notification-rule-name" label="Name">
              <Input
                id="notification-rule-name"
                required
                maxLength={160}
                value={draft.name}
                onChange={(event) =>
                  setDraft((current) => ({
                    ...current,
                    name: event.target.value,
                  }))
                }
              />
            </FormField>
            <FormField
              htmlFor="notification-rule-description"
              label="Description"
            >
              <Input
                id="notification-rule-description"
                required
                maxLength={500}
                value={draft.description}
                onChange={(event) =>
                  setDraft((current) => ({
                    ...current,
                    description: event.target.value,
                  }))
                }
              />
            </FormField>
            <NativeSelect
              id="notification-rule-event"
              label="Event"
              value={draft.eventType}
              options={eventTypes}
              onChange={(eventType) =>
                setDraft((current) => ({ ...current, eventType }))
              }
            />
            <NativeSelect
              id="notification-rule-object"
              label="Object"
              value={draft.objectType}
              options={objectTypes}
              onChange={(objectType) =>
                setDraft((current) => ({ ...current, objectType }))
              }
            />
            <NativeSelect
              id="notification-rule-channel"
              label="Channel"
              value={draft.channel}
              options={["email", "webhook"] as const}
              onChange={(channel) =>
                setDraft((current) => ({ ...current, channel }))
              }
            />
            <FormField htmlFor="notification-rule-template" label="Template ID">
              <Input
                id="notification-rule-template"
                required
                maxLength={160}
                value={draft.templateId}
                onChange={(event) =>
                  setDraft((current) => ({
                    ...current,
                    templateId: event.target.value,
                  }))
                }
              />
            </FormField>
            <FormField
              htmlFor="notification-rule-template-version"
              label="Template version"
            >
              <Input
                id="notification-rule-template-version"
                required
                type="number"
                min={1}
                value={draft.templateVersion}
                onChange={(event) =>
                  setDraft((current) => ({
                    ...current,
                    templateVersion: event.target.value,
                  }))
                }
              />
            </FormField>
            <FormField htmlFor="notification-rule-priority" label="Priority">
              <Input
                id="notification-rule-priority"
                required
                type="number"
                min={0}
                max={1000}
                value={draft.priority}
                onChange={(event) =>
                  setDraft((current) => ({
                    ...current,
                    priority: event.target.value,
                  }))
                }
              />
            </FormField>
            <FormField htmlFor="notification-rule-delay" label="Delay (ms)">
              <Input
                id="notification-rule-delay"
                required
                type="number"
                min={0}
                value={draft.delayMs}
                onChange={(event) =>
                  setDraft((current) => ({
                    ...current,
                    delayMs: event.target.value,
                  }))
                }
              />
            </FormField>
            <FormField
              htmlFor="notification-rule-effective"
              label="Effective from"
              hint="RFC 3339 instant"
            >
              <Input
                id="notification-rule-effective"
                required
                value={draft.effectiveFrom}
                onChange={(event) =>
                  setDraft((current) => ({
                    ...current,
                    effectiveFrom: event.target.value,
                  }))
                }
              />
            </FormField>
          </div>
          <FormField
            htmlFor="notification-rule-condition"
            label="Condition JSON"
            hint="Closed all, any, not, or predicate tree"
          >
            <Textarea
              id="notification-rule-condition"
              required
              rows={6}
              value={draft.condition}
              onChange={(event) =>
                setDraft((current) => ({
                  ...current,
                  condition: event.target.value,
                }))
              }
            />
          </FormField>
          <FormField
            htmlFor="notification-rule-recipients"
            label="Recipient selectors JSON"
          >
            <Textarea
              id="notification-rule-recipients"
              required
              rows={5}
              value={draft.recipients}
              onChange={(event) =>
                setDraft((current) => ({
                  ...current,
                  recipients: event.target.value,
                }))
              }
            />
          </FormField>
          <label className="notification-check">
            <input
              type="checkbox"
              checked={draft.enabled}
              onChange={(event) =>
                setDraft((current) => ({
                  ...current,
                  enabled: event.target.checked,
                }))
              }
            />{" "}
            Enable this version
          </label>
          <EditorActions
            busy={busy}
            submitLabel={editing === "new" ? "Create rule" : "Append version"}
          >
            <Button
              type="button"
              variant="ghost"
              onClick={() => setEditing(null)}
            >
              Close editor
            </Button>
          </EditorActions>
        </form>
      )}
    </aside>
  );
}

interface RuleInventoryProps {
  busy: boolean;
  createRule: () => void;
  editRule: (id: string) => Promise<void>;
  inventory: CursorInventory<NotificationRule>;
}

function RuleInventory({
  busy,
  createRule,
  editRule,
  inventory,
}: RuleInventoryProps): React.JSX.Element {
  return (
    <section
      className="notification-inventory"
      aria-busy={inventory.kind === "loading"}
    >
      <InventoryHeading
        busy={inventory.kind === "loading"}
        count={inventory.items.length}
        label="Routing rules"
        onRefresh={inventory.refresh}
      />
      {inventory.kind === "loading" ? (
        <NotificationLoading label="Loading routing rules" />
      ) : null}
      {inventory.error ? (
        <NotificationError
          error={inventory.error}
          fallback="Routing rules could not be loaded."
        />
      ) : null}
      {inventory.kind === "ready" && inventory.items.length === 0 ? (
        <NotificationEmpty
          title="No routing rules"
          detail="Create the first versioned rule to connect an event, audience, and channel."
          action={
            <Button type="button" onClick={createRule}>
              <Plus aria-hidden="true" /> Create rule
            </Button>
          }
        />
      ) : null}
      {inventory.items.length > 0 ? (
        <div className="notification-table-wrap">
          <Table>
            <TableColumnHeaders
              columns={["Rule", "Route", "State"]}
              actionLabel="Actions"
            />
            <TableBody>
              {inventory.items.map((rule) => (
                <TableRow key={rule.id}>
                  <TableCell>
                    <strong>{rule.name}</strong>
                    <small>{rule.description || "No description"}</small>
                  </TableCell>
                  <TableCell>
                    <code>{rule.eventType}</code>
                    <small>
                      {rule.channel} · priority {rule.priority}
                    </small>
                  </TableCell>
                  <TableCell>
                    <Badge variant={rule.enabled ? "secondary" : "outline"}>
                      {rule.enabled ? "Enabled" : "Paused"}
                    </Badge>
                    <small>
                      v{rule.version} ·{" "}
                      <TenantInstant value={rule.effectiveFrom} />
                    </small>
                  </TableCell>
                  <TableCell>
                    <Button
                      type="button"
                      size="sm"
                      variant="ghost"
                      disabled={busy}
                      onClick={() => void editRule(rule.id)}
                    >
                      <PencilLine aria-hidden="true" /> Version
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      ) : null}
      {inventory.nextCursor ? (
        <Button
          type="button"
          variant="outline"
          disabled={inventory.loadingMore}
          onClick={() => void inventory.loadMore()}
        >
          Load more rules
        </Button>
      ) : null}
      {inventory.items.length > 0 ? (
        <Button type="button" variant="outline" onClick={createRule}>
          <Plus aria-hidden="true" /> New rule
        </Button>
      ) : null}
    </section>
  );
}
