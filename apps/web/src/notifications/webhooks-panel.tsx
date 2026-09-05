import type {
  NotificationAudience,
  NotificationEventType,
  WebhookConfiguration,
  WebhookConfigurationWriteWritable,
} from "@periapsis/contracts";
import { Badge } from "@periapsis/ui/components/ui/badge";
import { Button } from "@periapsis/ui/components/ui/button";
import { Input } from "@periapsis/ui/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@periapsis/ui/components/ui/table";
import { Textarea } from "@periapsis/ui/components/ui/textarea";
import { KeyRound, PencilLine, Plus, Send } from "lucide-react";
import { useCallback, useRef, useState, type FormEvent } from "react";

import { FormField } from "../components/form-field";
import type { NotificationAdminApi, Versioned } from "./notification-api";
import {
  bindMutationAttempt,
  bindOpaqueMutationAttempt,
  emptyWebhookWrite,
  forgetWriteOnlyWebhook,
  parseSampleData,
  resetMutationAttempt,
  resetOpaqueMutationAttempt,
  type MutationAttemptReference,
  type OpaqueMutationAttemptReference,
} from "./model";
import {
  EditorActions,
  InventoryHeading,
  NotificationEmpty,
  NotificationError,
  NotificationLoading,
} from "./notification-primitives";
import { useCursorInventory } from "./use-cursor-inventory";

interface WebhookDraft {
  audience: NotificationAudience;
  enabled: boolean;
  endpointUrl: string;
  eventTypes: string;
  name: string;
  signingKey: string;
  timeoutMs: string;
}

interface WebhooksPanelProps {
  api: NotificationAdminApi;
  csrfToken: string;
  tenantId: string;
}

const notificationEventTypes = [
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
const notificationEventTypeSet: ReadonlySet<string> = new Set(
  notificationEventTypes,
);

export function WebhooksPanel({
  api,
  csrfToken,
  tenantId,
}: WebhooksPanelProps) {
  const load = useCallback(
    (after: string | undefined, signal: AbortSignal) =>
      api.listWebhooks({ ...(after ? { after } : {}), signal, tenantId }),
    [api, tenantId],
  );
  const inventory = useCursorInventory(load);
  const [editing, setEditing] = useState<
    Versioned<WebhookConfiguration> | "new" | null
  >(null);
  const [draft, setDraft] = useState<WebhookDraft>(() =>
    webhookDraft(emptyWebhookWrite),
  );
  const [busy, setBusy] = useState<"save" | "test" | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [testEvent, setTestEvent] =
    useState<NotificationEventType>("webhook.custom");
  const [testContext, setTestContext] = useState("{}");
  const [reason, setReason] = useState("");
  const saveAttempt = useRef<OpaqueMutationAttemptReference>({ current: null });
  const testAttempt = useRef<MutationAttemptReference>({ current: null });

  function updateDraft(change: (current: WebhookDraft) => WebhookDraft): void {
    resetOpaqueMutationAttempt(saveAttempt.current);
    setDraft(change);
  }

  async function editWebhook(id: string): Promise<void> {
    setBusy("save");
    setError(null);
    try {
      const current = await api.getWebhook({ id, tenantId });
      setEditing(current);
      setDraft(webhookDraft(current.value));
      resetOpaqueMutationAttempt(saveAttempt.current);
      resetMutationAttempt(testAttempt.current);
    } catch (caught: unknown) {
      setError(caught);
    } finally {
      setBusy(null);
    }
  }

  function createWebhook(): void {
    setEditing("new");
    setDraft(webhookDraft(emptyWebhookWrite));
    setError(null);
    setNotice(null);
    resetOpaqueMutationAttempt(saveAttempt.current);
  }

  async function save(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (!editing) return;
    setBusy("save");
    setError(null);
    setNotice(null);
    try {
      const body = webhookWrite(draft);
      const idempotencyKey = bindOpaqueMutationAttempt(saveAttempt.current);
      const saved =
        editing === "new"
          ? await api.createWebhook({
              body,
              csrfToken,
              idempotencyKey,
              tenantId,
            })
          : await api.versionWebhook({
              body,
              csrfToken,
              etag: editing.etag,
              id: editing.value.id,
              idempotencyKey,
              tenantId,
            });
      inventory.upsert(saved.value, (item) => item.id);
      setEditing(saved);
      setDraft(webhookDraft(forgetWriteOnlyWebhook(saved.value)));
      setNotice(
        `Webhook version ${saved.value.version} is current. The signing key was cleared.`,
      );
      resetOpaqueMutationAttempt(saveAttempt.current);
    } catch (caught: unknown) {
      setError(caught);
    } finally {
      setBusy(null);
    }
  }

  async function sendTest(): Promise<void> {
    if (editing === null || editing === "new") return;
    setBusy("test");
    setError(null);
    try {
      const body = {
        configurationVersion: editing.value.version,
        eventType: testEvent,
        context: parseSampleData(testContext),
        reason: reason.trim(),
      };
      const delivery = await api.testWebhook({
        body,
        csrfToken,
        id: editing.value.id,
        idempotencyKey: bindMutationAttempt(
          testAttempt.current,
          "webhook.test",
          tenantId,
          body,
        ),
        tenantId,
      });
      setNotice(
        `Signed test delivery ${delivery.id} queued for ${delivery.destinationRedacted}.`,
      );
      resetMutationAttempt(testAttempt.current);
    } catch (caught: unknown) {
      setError(caught);
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="notification-panel-grid">
      <section
        className="notification-inventory"
        aria-busy={inventory.kind === "loading"}
      >
        <InventoryHeading
          busy={inventory.kind === "loading"}
          count={inventory.items.length}
          label="Signed webhooks"
          onRefresh={inventory.refresh}
        />
        {inventory.kind === "loading" ? (
          <NotificationLoading label="Loading webhook configurations" />
        ) : null}
        {inventory.error ? (
          <NotificationError
            error={inventory.error}
            fallback="Webhook configurations could not be loaded."
          />
        ) : null}
        {inventory.kind === "ready" && inventory.items.length === 0 ? (
          <NotificationEmpty
            title="No webhooks"
            detail="Create an HTTPS endpoint with a write-only signing key."
            action={
              <Button type="button" onClick={createWebhook}>
                <Plus aria-hidden="true" /> Create webhook
              </Button>
            }
          />
        ) : null}
        {inventory.items.length > 0 ? (
          <div className="notification-table-wrap">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Endpoint</TableHead>
                  <TableHead>Audience</TableHead>
                  <TableHead>Current</TableHead>
                  <TableHead>
                    <span className="sr-only">Actions</span>
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {inventory.items.map((webhook) => (
                  <TableRow key={webhook.id}>
                    <TableCell>
                      <strong>{webhook.name}</strong>
                      <small className="notification-endpoint">
                        {webhook.endpointUrl}
                      </small>
                    </TableCell>
                    <TableCell>
                      {webhook.audience}
                      <small>{webhook.eventTypes.length} events</small>
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant={webhook.enabled ? "secondary" : "outline"}
                      >
                        {webhook.enabled ? "Enabled" : "Paused"}
                      </Badge>
                      <small>
                        v{webhook.version} · key v{webhook.signingKeyVersion}
                      </small>
                    </TableCell>
                    <TableCell>
                      <Button
                        type="button"
                        size="sm"
                        variant="ghost"
                        disabled={busy !== null}
                        onClick={() => void editWebhook(webhook.id)}
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
            Load more webhooks
          </Button>
        ) : null}
        {inventory.items.length > 0 ? (
          <Button type="button" variant="outline" onClick={createWebhook}>
            <Plus aria-hidden="true" /> New webhook
          </Button>
        ) : null}
      </section>

      <aside
        className="notification-editor"
        aria-label="Webhook configuration editor"
      >
        {!editing ? (
          <NotificationEmpty
            title="Select a webhook"
            detail="Open a sanitized endpoint to append a version or run a signed test."
          />
        ) : (
          <form onSubmit={(event) => void save(event)}>
            <header>
              <div>
                <p className="section-label">
                  {editing === "new"
                    ? "New endpoint"
                    : `Webhook ${editing.value.id}`}
                </p>
                <h2>
                  {editing === "new"
                    ? "Create signed webhook"
                    : `Append version ${editing.value.version + 1}`}
                </h2>
              </div>
              {editing !== "new" ? (
                <Badge variant="outline">{editing.etag}</Badge>
              ) : null}
            </header>
            <p className="notification-secret-note">
              <KeyRound aria-hidden="true" /> Signing keys are write-only. Blank
              retains the encrypted key on versioning.
            </p>
            {error ? (
              <NotificationError
                error={error}
                fallback="The webhook action could not be completed."
              />
            ) : null}
            {notice ? (
              <p className="notification-notice" role="status">
                {notice}
              </p>
            ) : null}
            <div className="notification-form-grid">
              <FormField htmlFor="webhook-name" label="Name">
                <Input
                  id="webhook-name"
                  required
                  maxLength={160}
                  value={draft.name}
                  onChange={(event) =>
                    updateDraft((current) => ({
                      ...current,
                      name: event.target.value,
                    }))
                  }
                />
              </FormField>
              <FormField htmlFor="webhook-url" label="HTTPS endpoint">
                <Input
                  id="webhook-url"
                  required
                  type="url"
                  maxLength={2048}
                  value={draft.endpointUrl}
                  onChange={(event) =>
                    updateDraft((current) => ({
                      ...current,
                      endpointUrl: event.target.value,
                    }))
                  }
                />
              </FormField>
              <FormField
                htmlFor="webhook-events"
                label="Event types"
                hint="Comma-separated closed event names"
              >
                <Input
                  id="webhook-events"
                  required
                  value={draft.eventTypes}
                  onChange={(event) =>
                    updateDraft((current) => ({
                      ...current,
                      eventTypes: event.target.value,
                    }))
                  }
                />
              </FormField>
              <label>
                Audience
                <select
                  value={draft.audience}
                  onChange={(event) => {
                    const audience = parseAudience(event.target.value);
                    if (audience) {
                      updateDraft((current) => ({ ...current, audience }));
                    }
                  }}
                >
                  <option value="operator">operator</option>
                  <option value="customer">customer</option>
                </select>
              </label>
              <FormField htmlFor="webhook-timeout" label="Timeout (ms)">
                <Input
                  id="webhook-timeout"
                  required
                  type="number"
                  min={100}
                  value={draft.timeoutMs}
                  onChange={(event) =>
                    updateDraft((current) => ({
                      ...current,
                      timeoutMs: event.target.value,
                    }))
                  }
                />
              </FormField>
              <FormField
                htmlFor="webhook-key"
                label="New signing key"
                optional
                hint="Never returned by the API"
              >
                <Input
                  id="webhook-key"
                  type="password"
                  autoComplete="new-password"
                  value={draft.signingKey}
                  onChange={(event) =>
                    updateDraft((current) => ({
                      ...current,
                      signingKey: event.target.value,
                    }))
                  }
                />
              </FormField>
            </div>
            <label className="notification-check">
              <input
                type="checkbox"
                checked={draft.enabled}
                onChange={(event) =>
                  updateDraft((current) => ({
                    ...current,
                    enabled: event.target.checked,
                  }))
                }
              />{" "}
              Endpoint enabled
            </label>
            <EditorActions
              busy={busy === "save"}
              submitLabel={
                editing === "new" ? "Create webhook" : "Append version"
              }
            >
              <Button
                type="button"
                variant="ghost"
                onClick={() => setEditing(null)}
              >
                Close
              </Button>
            </EditorActions>
            {editing !== "new" ? (
              <section className="notification-toolbox">
                <h3>Signed test event</h3>
                <div className="notification-form-grid">
                  <FormField htmlFor="webhook-test-event" label="Event type">
                    <select
                      id="webhook-test-event"
                      value={testEvent}
                      onChange={(event) => {
                        const eventType = parseEventType(event.target.value);
                        if (eventType) {
                          setTestEvent(eventType);
                          resetMutationAttempt(testAttempt.current);
                        }
                      }}
                    >
                      {notificationEventTypes.map((eventType) => (
                        <option key={eventType} value={eventType}>
                          {eventType}
                        </option>
                      ))}
                    </select>
                  </FormField>
                  <FormField
                    htmlFor="webhook-test-reason"
                    label="Audited reason"
                  >
                    <Input
                      id="webhook-test-reason"
                      value={reason}
                      onChange={(event) => {
                        setReason(event.target.value);
                        resetMutationAttempt(testAttempt.current);
                      }}
                    />
                  </FormField>
                  <FormField
                    htmlFor="webhook-test-context"
                    label="Context JSON"
                  >
                    <Textarea
                      id="webhook-test-context"
                      rows={4}
                      value={testContext}
                      onChange={(event) => {
                        setTestContext(event.target.value);
                        resetMutationAttempt(testAttempt.current);
                      }}
                    />
                  </FormField>
                </div>
                <Button
                  type="button"
                  variant="outline"
                  disabled={busy !== null || !reason.trim()}
                  onClick={() => void sendTest()}
                >
                  <Send aria-hidden="true" /> Queue signed test
                </Button>
              </section>
            ) : null}
          </form>
        )}
      </aside>
    </div>
  );
}

function webhookDraft(value: WebhookConfigurationWriteWritable): WebhookDraft {
  return {
    audience: value.audience,
    enabled: value.enabled,
    endpointUrl: value.endpointUrl,
    eventTypes: value.eventTypes.join(", "),
    name: value.name,
    signingKey: value.signingKey ?? "",
    timeoutMs: String(value.timeoutMs),
  };
}

function webhookWrite(draft: WebhookDraft): WebhookConfigurationWriteWritable {
  const eventTypes = [
    ...new Set(
      draft.eventTypes
        .split(",")
        .map((value) => value.trim())
        .filter(Boolean),
    ),
  ];
  if (eventTypes.length === 0 || !eventTypes.every(isEventType)) {
    throw new TypeError(
      "Webhook event types must use the closed event catalog.",
    );
  }
  return {
    name: draft.name.trim(),
    endpointUrl: draft.endpointUrl.trim(),
    eventTypes,
    audience: draft.audience,
    ...(draft.signingKey ? { signingKey: draft.signingKey } : {}),
    timeoutMs: Number(draft.timeoutMs),
    enabled: draft.enabled,
  };
}

function parseAudience(value: string): NotificationAudience | undefined {
  return value === "operator" || value === "customer" ? value : undefined;
}

function parseEventType(value: string): NotificationEventType | undefined {
  return isEventType(value) ? value : undefined;
}

function isEventType(value: string): value is NotificationEventType {
  return notificationEventTypeSet.has(value);
}
