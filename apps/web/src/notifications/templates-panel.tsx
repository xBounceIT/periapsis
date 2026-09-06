import type {
  NotificationAudience,
  NotificationTemplate,
  NotificationTemplatePreview,
  NotificationTemplateWrite,
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
import {
  Beaker,
  CopyPlus,
  PencilLine,
  Plus,
  RotateCcw,
  Send,
} from "lucide-react";
import { useCallback, useRef, useState, type FormEvent } from "react";
import { TableColumnHeaders } from "../components/table-column-headers";
import { isolateTemplatePreview } from "./templates-panel-model";

import { FormField } from "../components/form-field";
import { TenantInstant } from "../lib/tenant-date-time-context";
import {
  bindMutationAttempt,
  emptyTemplateWrite,
  parseSampleData,
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

interface TemplateDraft {
  css: string;
  html: string;
  key: string;
  language: string;
  name: string;
  plainText: string;
  sampleData: string;
  subject: string;
}

interface TemplatesPanelProps {
  api: NotificationAdminApi;
  csrfToken: string;
  tenantId: string;
}

type TemplateOperation = "duplicate" | "preview" | "rollback" | "save" | "test";

export function TemplatesPanel(props: TemplatesPanelProps) {
  const model = useTemplatesPanelModel(props);
  return <TemplatesPanelView model={model.data} />;
}

function useTemplatesPanelModel({
  api,
  csrfToken,
  tenantId,
}: TemplatesPanelProps) {
  const load = useCallback(
    (after: string | undefined, signal: AbortSignal) =>
      api.listTemplates({ ...(after ? { after } : {}), signal, tenantId }),
    [api, tenantId],
  );
  const inventory = useCursorInventory(load);
  const [editing, setEditing] = useState<
    Versioned<NotificationTemplate> | "new" | null
  >(null);
  const [draft, setDraft] = useState<TemplateDraft>(() =>
    draftFromTemplate(emptyTemplateWrite),
  );
  const [operation, setOperation] = useState<TemplateOperation | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [preview, setPreview] = useState<NotificationTemplatePreview | null>(
    null,
  );
  const [previewAudience, setPreviewAudience] =
    useState<NotificationAudience>("operator");
  const [previewContext, setPreviewContext] = useState("{}");
  const [duplicateKey, setDuplicateKey] = useState("");
  const [duplicateName, setDuplicateName] = useState("");
  const [rollbackVersion, setRollbackVersion] = useState("1");
  const [reason, setReason] = useState("");
  const [testRecipient, setTestRecipient] = useState("");
  const [testAudience, setTestAudience] =
    useState<NotificationAudience>("operator");
  const attempts = useRef<
    Record<Exclude<TemplateOperation, "preview">, MutationAttemptReference>
  >({
    duplicate: { current: null },
    rollback: { current: null },
    save: { current: null },
    test: { current: null },
  });

  async function editTemplate(id: string): Promise<void> {
    setOperation("save");
    setError(null);
    try {
      const current = await api.getTemplate({ id, tenantId });
      setEditing(current);
      setDraft(draftFromTemplate(current.value));
      setRollbackVersion(String(Math.max(1, current.value.version - 1)));
      setDuplicateKey(`${current.value.key}-copy`);
      setDuplicateName(`${current.value.name} copy`);
      clearAttempts();
    } catch (caught: unknown) {
      setError(caught);
    } finally {
      setOperation(null);
    }
  }

  function createTemplate(): void {
    setEditing("new");
    setDraft(draftFromTemplate(emptyTemplateWrite));
    setPreview(null);
    setError(null);
    setNotice(null);
    clearAttempts();
  }

  async function saveTemplate(
    event: FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault();
    if (!editing) return;
    setOperation("save");
    setError(null);
    setNotice(null);
    try {
      const body = templateFromDraft(draft);
      const idempotencyKey = bindMutationAttempt(
        attempts.current.save,
        editing === "new"
          ? "notification-template.create"
          : "notification-template.version",
        tenantId,
        body,
      );
      const saved =
        editing === "new"
          ? await api.createTemplate({
              body,
              csrfToken,
              idempotencyKey,
              tenantId,
            })
          : await api.versionTemplate({
              body,
              csrfToken,
              etag: editing.etag,
              id: editing.value.id,
              idempotencyKey,
              tenantId,
            });
      inventory.upsert(saved.value, (item) => item.id);
      setEditing(saved);
      setDraft(draftFromTemplate(saved.value));
      setNotice(`Template version ${saved.value.version} is current.`);
      resetMutationAttempt(attempts.current.save);
    } catch (caught: unknown) {
      setError(caught);
    } finally {
      setOperation(null);
    }
  }

  async function renderPreview(): Promise<void> {
    setOperation("preview");
    setError(null);
    try {
      setPreview(
        await api.previewTemplate({
          body: {
            audience: previewAudience,
            context: parseSampleData(previewContext),
            template: templateFromDraft(draft),
          },
          csrfToken,
          tenantId,
        }),
      );
    } catch (caught: unknown) {
      setError(caught);
      setPreview(null);
    } finally {
      setOperation(null);
    }
  }

  async function duplicateTemplate(): Promise<void> {
    if (editing === null || editing === "new") return;
    setOperation("duplicate");
    setError(null);
    try {
      const body = {
        sourceVersion: editing.value.version,
        key: duplicateKey.trim(),
        name: duplicateName.trim(),
      };
      const saved = await api.duplicateTemplate({
        body,
        csrfToken,
        id: editing.value.id,
        idempotencyKey: bindMutationAttempt(
          attempts.current.duplicate,
          "notification-template.duplicate",
          tenantId,
          body,
        ),
        tenantId,
      });
      inventory.upsert(saved.value, (item) => item.id);
      setEditing(saved);
      setDraft(draftFromTemplate(saved.value));
      setNotice(`Duplicated as ${saved.value.name}.`);
      resetMutationAttempt(attempts.current.duplicate);
    } catch (caught: unknown) {
      setError(caught);
    } finally {
      setOperation(null);
    }
  }

  async function rollbackTemplate(): Promise<void> {
    if (editing === null || editing === "new") return;
    setOperation("rollback");
    setError(null);
    try {
      const body = {
        sourceVersion: Number(rollbackVersion),
        reason: reason.trim(),
      };
      const saved = await api.rollbackTemplate({
        body,
        csrfToken,
        etag: editing.etag,
        id: editing.value.id,
        idempotencyKey: bindMutationAttempt(
          attempts.current.rollback,
          "notification-template.rollback",
          tenantId,
          body,
        ),
        tenantId,
      });
      inventory.upsert(saved.value, (item) => item.id);
      setEditing(saved);
      setDraft(draftFromTemplate(saved.value));
      setNotice(
        `Version ${body.sourceVersion} was restored as version ${saved.value.version}.`,
      );
      resetMutationAttempt(attempts.current.rollback);
    } catch (caught: unknown) {
      setError(caught);
    } finally {
      setOperation(null);
    }
  }

  async function sendTest(): Promise<void> {
    if (editing === null || editing === "new") return;
    setOperation("test");
    setError(null);
    try {
      const body = {
        version: editing.value.version,
        recipient: testRecipient.trim(),
        audience: testAudience,
        context: parseSampleData(previewContext),
        reason: reason.trim(),
      };
      const delivery = await api.testTemplate({
        body,
        csrfToken,
        id: editing.value.id,
        idempotencyKey: bindMutationAttempt(
          attempts.current.test,
          "notification-template.test-send",
          tenantId,
          body,
        ),
        tenantId,
      });
      setNotice(
        `Test delivery ${delivery.id} queued for ${delivery.destinationRedacted}.`,
      );
      resetMutationAttempt(attempts.current.test);
      setTestRecipient("");
    } catch (caught: unknown) {
      setError(caught);
    } finally {
      setOperation(null);
    }
  }

  function clearAttempts(): void {
    for (const reference of Object.values(attempts.current))
      resetMutationAttempt(reference);
  }

  return {
    kind: "ready" as const,
    data: {
      createTemplate,
      draft,
      duplicateKey,
      duplicateName,
      duplicateTemplate,
      editTemplate,
      editing,
      error,
      inventory,
      notice,
      operation,
      preview,
      previewAudience,
      previewContext,
      reason,
      renderPreview,
      rollbackTemplate,
      rollbackVersion,
      saveTemplate,
      sendTest,
      setDraft,
      setDuplicateKey,
      setDuplicateName,
      setEditing,
      setPreviewAudience,
      setPreviewContext,
      setReason,
      setRollbackVersion,
      setTestAudience,
      setTestRecipient,
      testAudience,
      testRecipient,
    },
  };
}

function TemplatesPanelView({
  model,
}: {
  model: Extract<
    ReturnType<typeof useTemplatesPanelModel>,
    { kind: "ready" }
  >["data"];
}): React.JSX.Element {
  const {
    createTemplate,
    draft,
    duplicateKey,
    duplicateName,
    duplicateTemplate,
    editTemplate,
    editing,
    error,
    inventory,
    notice,
    operation,
    preview,
    previewAudience,
    previewContext,
    reason,
    renderPreview,
    rollbackTemplate,
    rollbackVersion,
    saveTemplate,
    sendTest,
    setDraft,
    setDuplicateKey,
    setDuplicateName,
    setEditing,
    setPreviewAudience,
    setPreviewContext,
    setReason,
    setRollbackVersion,
    setTestAudience,
    setTestRecipient,
    testAudience,
    testRecipient,
  } = model;
  return (
    <div className="notification-panel-grid notification-panel-grid--wide-editor">
      <TemplateInventory
        createTemplate={createTemplate}
        editTemplate={editTemplate}
        inventory={inventory}
        operation={operation}
      />

      <TemplateEditor
        draft={draft}
        duplicateKey={duplicateKey}
        duplicateName={duplicateName}
        duplicateTemplate={duplicateTemplate}
        editing={editing}
        error={error}
        notice={notice}
        operation={operation}
        preview={preview}
        previewAudience={previewAudience}
        previewContext={previewContext}
        reason={reason}
        renderPreview={renderPreview}
        rollbackTemplate={rollbackTemplate}
        rollbackVersion={rollbackVersion}
        saveTemplate={saveTemplate}
        sendTest={sendTest}
        setDraft={setDraft}
        setDuplicateKey={setDuplicateKey}
        setDuplicateName={setDuplicateName}
        setEditing={setEditing}
        setPreviewAudience={setPreviewAudience}
        setPreviewContext={setPreviewContext}
        setReason={setReason}
        setRollbackVersion={setRollbackVersion}
        setTestAudience={setTestAudience}
        setTestRecipient={setTestRecipient}
        testAudience={testAudience}
        testRecipient={testRecipient}
      />
    </div>
  );
}

function draftFromTemplate(value: NotificationTemplateWrite): TemplateDraft {
  return {
    css: value.css ?? "",
    html: value.html,
    key: value.key,
    language: value.language,
    name: value.name,
    plainText: value.plainText ?? "",
    sampleData: JSON.stringify(value.sampleData ?? {}, null, 2),
    subject: value.subject,
  };
}

function templateFromDraft(draft: TemplateDraft): NotificationTemplateWrite {
  return {
    key: draft.key.trim(),
    name: draft.name.trim(),
    language: draft.language.trim(),
    subject: draft.subject.trim(),
    html: draft.html,
    ...(draft.plainText.trim() ? { plainText: draft.plainText } : {}),
    ...(draft.css.trim() ? { css: draft.css } : {}),
    sampleData: parseSampleData(draft.sampleData),
  };
}

function parseAudience(value: string): NotificationAudience | undefined {
  return value === "operator" || value === "customer" ? value : undefined;
}

interface TemplateVersionActionsProps {
  duplicateKey: string;
  duplicateName: string;
  duplicateTemplate: () => Promise<void>;
  operation: TemplateOperation | null;
  reason: string;
  rollbackTemplate: () => Promise<void>;
  rollbackVersion: string;
  sendTest: () => Promise<void>;
  setDuplicateKey: React.Dispatch<React.SetStateAction<string>>;
  setDuplicateName: React.Dispatch<React.SetStateAction<string>>;
  setReason: React.Dispatch<React.SetStateAction<string>>;
  setRollbackVersion: React.Dispatch<React.SetStateAction<string>>;
  setTestAudience: React.Dispatch<React.SetStateAction<NotificationAudience>>;
  setTestRecipient: React.Dispatch<React.SetStateAction<string>>;
  testAudience: NotificationAudience;
  testRecipient: string;
}

function TemplateVersionActions({
  duplicateKey,
  duplicateName,
  duplicateTemplate,
  operation,
  reason,
  rollbackTemplate,
  rollbackVersion,
  sendTest,
  setDuplicateKey,
  setDuplicateName,
  setReason,
  setRollbackVersion,
  setTestAudience,
  setTestRecipient,
  testAudience,
  testRecipient,
}: TemplateVersionActionsProps): React.JSX.Element {
  return (
    <section
      className="notification-toolbox"
      aria-labelledby="template-version-tools"
    >
      <h3 id="template-version-tools">Version operations</h3>
      <div className="notification-form-grid">
        <FormField htmlFor="template-duplicate-key" label="Duplicate key">
          <Input
            id="template-duplicate-key"
            value={duplicateKey}
            onChange={(event) => setDuplicateKey(event.target.value)}
          />
        </FormField>
        <FormField htmlFor="template-duplicate-name" label="Duplicate name">
          <Input
            id="template-duplicate-name"
            value={duplicateName}
            onChange={(event) => setDuplicateName(event.target.value)}
          />
        </FormField>
        <FormField
          htmlFor="template-rollback-version"
          label="Rollback source version"
        >
          <Input
            id="template-rollback-version"
            type="number"
            min={1}
            value={rollbackVersion}
            onChange={(event) => setRollbackVersion(event.target.value)}
          />
        </FormField>
        <FormField htmlFor="template-reason" label="Audited reason">
          <Input
            id="template-reason"
            maxLength={500}
            value={reason}
            onChange={(event) => setReason(event.target.value)}
          />
        </FormField>
        <FormField
          htmlFor="template-test-recipient"
          label="Test recipient"
          hint="Write-only request value"
        >
          <Input
            id="template-test-recipient"
            type="email"
            autoComplete="off"
            value={testRecipient}
            onChange={(event) => setTestRecipient(event.target.value)}
          />
        </FormField>
        <label>
          Test audience
          <select
            value={testAudience}
            onChange={(event) => {
              const audience = parseAudience(event.target.value);
              if (audience) setTestAudience(audience);
            }}
          >
            <option value="operator">operator</option>
            <option value="customer">customer</option>
          </select>
        </label>
      </div>
      <div className="notification-editor__actions">
        <Button
          type="button"
          variant="outline"
          disabled={
            operation !== null || !duplicateKey.trim() || !duplicateName.trim()
          }
          onClick={() => void duplicateTemplate()}
        >
          <CopyPlus aria-hidden="true" /> Duplicate
        </Button>
        <Button
          type="button"
          variant="outline"
          disabled={operation !== null || !reason.trim()}
          onClick={() => void rollbackTemplate()}
        >
          <RotateCcw aria-hidden="true" /> Roll back
        </Button>
        <Button
          type="button"
          variant="outline"
          disabled={
            operation !== null || !reason.trim() || !testRecipient.trim()
          }
          onClick={() => void sendTest()}
        >
          <Send aria-hidden="true" /> Send test
        </Button>
      </div>
    </section>
  );
}

interface TemplateEditorProps {
  draft: TemplateDraft;
  duplicateKey: string;
  duplicateName: string;
  duplicateTemplate: () => Promise<void>;
  editing: Versioned<NotificationTemplate> | "new" | null;
  error: unknown;
  notice: string | null;
  operation: TemplateOperation | null;
  preview: NotificationTemplatePreview | null;
  previewAudience: NotificationAudience;
  previewContext: string;
  reason: string;
  renderPreview: () => Promise<void>;
  rollbackTemplate: () => Promise<void>;
  rollbackVersion: string;
  saveTemplate: (event: FormEvent<HTMLFormElement>) => Promise<void>;
  sendTest: () => Promise<void>;
  setDraft: React.Dispatch<React.SetStateAction<TemplateDraft>>;
  setDuplicateKey: React.Dispatch<React.SetStateAction<string>>;
  setDuplicateName: React.Dispatch<React.SetStateAction<string>>;
  setEditing: React.Dispatch<
    React.SetStateAction<Versioned<NotificationTemplate> | "new" | null>
  >;
  setPreviewAudience: React.Dispatch<
    React.SetStateAction<NotificationAudience>
  >;
  setPreviewContext: React.Dispatch<React.SetStateAction<string>>;
  setReason: React.Dispatch<React.SetStateAction<string>>;
  setRollbackVersion: React.Dispatch<React.SetStateAction<string>>;
  setTestAudience: React.Dispatch<React.SetStateAction<NotificationAudience>>;
  setTestRecipient: React.Dispatch<React.SetStateAction<string>>;
  testAudience: NotificationAudience;
  testRecipient: string;
}

function TemplateEditor({
  draft,
  duplicateKey,
  duplicateName,
  duplicateTemplate,
  editing,
  error,
  notice,
  operation,
  preview,
  previewAudience,
  previewContext,
  reason,
  renderPreview,
  rollbackTemplate,
  rollbackVersion,
  saveTemplate,
  sendTest,
  setDraft,
  setDuplicateKey,
  setDuplicateName,
  setEditing,
  setPreviewAudience,
  setPreviewContext,
  setReason,
  setRollbackVersion,
  setTestAudience,
  setTestRecipient,
  testAudience,
  testRecipient,
}: TemplateEditorProps): React.JSX.Element {
  return (
    <aside
      className="notification-editor notification-template-editor"
      aria-label="Template editor"
    >
      {!editing ? (
        <NotificationEmpty
          title="Select a template"
          detail="Open a current template for preview, versioning, rollback, duplication, and test delivery."
        />
      ) : (
        <form onSubmit={(event) => void saveTemplate(event)}>
          <header>
            <div>
              <p className="section-label">
                {editing === "new"
                  ? "New lineage"
                  : `Template ${editing.value.id}`}
              </p>
              <h2>
                {editing === "new"
                  ? "Create template"
                  : `Edit version ${editing.value.version}`}
              </h2>
            </div>
            {editing !== "new" ? (
              <Badge variant="outline">{editing.etag}</Badge>
            ) : null}
          </header>
          {error ? (
            <NotificationError
              error={error}
              fallback="The template action could not be completed."
            />
          ) : null}
          {notice ? (
            <p className="notification-notice" role="status">
              {notice}
            </p>
          ) : null}
          <TemplateMessageFields draft={draft} setDraft={setDraft} />
          <FormField htmlFor="template-html" label="HTML">
            <Textarea
              id="template-html"
              required
              rows={8}
              value={draft.html}
              onChange={(event) =>
                setDraft((current) => ({
                  ...current,
                  html: event.target.value,
                }))
              }
            />
          </FormField>
          <FormField
            htmlFor="template-plain"
            label="Plaintext fallback"
            optional
          >
            <Textarea
              id="template-plain"
              rows={5}
              value={draft.plainText}
              onChange={(event) =>
                setDraft((current) => ({
                  ...current,
                  plainText: event.target.value,
                }))
              }
            />
          </FormField>
          <div className="notification-form-grid">
            <FormField htmlFor="template-css" label="Scoped CSS" optional>
              <Textarea
                id="template-css"
                rows={4}
                value={draft.css}
                onChange={(event) =>
                  setDraft((current) => ({
                    ...current,
                    css: event.target.value,
                  }))
                }
              />
            </FormField>
            <FormField
              htmlFor="template-sample"
              label="Sample data JSON"
              optional
            >
              <Textarea
                id="template-sample"
                rows={4}
                value={draft.sampleData}
                onChange={(event) =>
                  setDraft((current) => ({
                    ...current,
                    sampleData: event.target.value,
                  }))
                }
              />
            </FormField>
          </div>
          <EditorActions
            busy={operation === "save"}
            submitLabel={
              editing === "new" ? "Create template" : "Append version"
            }
          >
            <Button
              type="button"
              variant="outline"
              disabled={operation !== null}
              onClick={() => void renderPreview()}
            >
              <Beaker aria-hidden="true" /> Preview draft
            </Button>
            <Button
              type="button"
              variant="ghost"
              onClick={() => setEditing(null)}
            >
              Close
            </Button>
          </EditorActions>

          <TemplateSandboxPreview
            preview={preview}
            previewAudience={previewAudience}
            previewContext={previewContext}
            setPreviewAudience={setPreviewAudience}
            setPreviewContext={setPreviewContext}
          />

          {editing !== "new" ? (
            <TemplateVersionActions
              duplicateKey={duplicateKey}
              duplicateName={duplicateName}
              duplicateTemplate={duplicateTemplate}
              operation={operation}
              reason={reason}
              rollbackTemplate={rollbackTemplate}
              rollbackVersion={rollbackVersion}
              sendTest={sendTest}
              setDuplicateKey={setDuplicateKey}
              setDuplicateName={setDuplicateName}
              setReason={setReason}
              setRollbackVersion={setRollbackVersion}
              setTestAudience={setTestAudience}
              setTestRecipient={setTestRecipient}
              testAudience={testAudience}
              testRecipient={testRecipient}
            />
          ) : null}
        </form>
      )}
    </aside>
  );
}

interface TemplateInventoryProps {
  createTemplate: () => void;
  editTemplate: (id: string) => Promise<void>;
  inventory: CursorInventory<NotificationTemplate>;
  operation: TemplateOperation | null;
}

function TemplateInventory({
  createTemplate,
  editTemplate,
  inventory,
  operation,
}: TemplateInventoryProps): React.JSX.Element {
  return (
    <section
      className="notification-inventory"
      aria-busy={inventory.kind === "loading"}
    >
      <InventoryHeading
        busy={inventory.kind === "loading"}
        count={inventory.items.length}
        label="Message templates"
        onRefresh={inventory.refresh}
      />
      {inventory.kind === "loading" ? (
        <NotificationLoading label="Loading templates" />
      ) : null}
      {inventory.error ? (
        <NotificationError
          error={inventory.error}
          fallback="Templates could not be loaded."
        />
      ) : null}
      {inventory.kind === "ready" && inventory.items.length === 0 ? (
        <NotificationEmpty
          title="No templates"
          detail="Build a versioned subject, HTML, and plaintext fallback."
          action={
            <Button type="button" onClick={createTemplate}>
              <Plus aria-hidden="true" /> Create template
            </Button>
          }
        />
      ) : null}
      {inventory.items.length > 0 ? (
        <div className="notification-table-wrap">
          <Table>
            <TableColumnHeaders
              columns={["Template", "Language", "Current"]}
              actionLabel="Actions"
            />
            <TableBody>
              {inventory.items.map((template) => (
                <TableRow key={template.id}>
                  <TableCell>
                    <strong>{template.name}</strong>
                    <code>{template.key}</code>
                  </TableCell>
                  <TableCell>
                    {template.language}
                    <small>{template.placeholders.length} placeholders</small>
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline">v{template.version}</Badge>
                    <small>
                      <TenantInstant value={template.createdAt} />
                    </small>
                  </TableCell>
                  <TableCell>
                    <Button
                      type="button"
                      size="sm"
                      variant="ghost"
                      disabled={operation !== null}
                      onClick={() => void editTemplate(template.id)}
                    >
                      <PencilLine aria-hidden="true" /> Open
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
          Load more templates
        </Button>
      ) : null}
      {inventory.items.length > 0 ? (
        <Button type="button" variant="outline" onClick={createTemplate}>
          <Plus aria-hidden="true" /> New template
        </Button>
      ) : null}
    </section>
  );
}

interface TemplateMessageFieldsProps {
  draft: TemplateDraft;
  setDraft: React.Dispatch<React.SetStateAction<TemplateDraft>>;
}

function TemplateMessageFields({
  draft,
  setDraft,
}: TemplateMessageFieldsProps): React.JSX.Element {
  return (
    <div className="notification-form-grid">
      <FormField htmlFor="template-key" label="Key">
        <Input
          id="template-key"
          required
          maxLength={120}
          value={draft.key}
          onChange={(event) =>
            setDraft((current) => ({
              ...current,
              key: event.target.value,
            }))
          }
        />
      </FormField>
      <FormField htmlFor="template-name" label="Name">
        <Input
          id="template-name"
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
      <FormField htmlFor="template-language" label="Language">
        <Input
          id="template-language"
          required
          maxLength={35}
          value={draft.language}
          onChange={(event) =>
            setDraft((current) => ({
              ...current,
              language: event.target.value,
            }))
          }
        />
      </FormField>
      <FormField htmlFor="template-subject" label="Subject">
        <Input
          id="template-subject"
          required
          maxLength={300}
          value={draft.subject}
          onChange={(event) =>
            setDraft((current) => ({
              ...current,
              subject: event.target.value,
            }))
          }
        />
      </FormField>
    </div>
  );
}

interface TemplateSandboxPreviewProps {
  preview: NotificationTemplatePreview | null;
  previewAudience: NotificationAudience;
  previewContext: string;
  setPreviewAudience: React.Dispatch<
    React.SetStateAction<NotificationAudience>
  >;
  setPreviewContext: React.Dispatch<React.SetStateAction<string>>;
}

function TemplateSandboxPreview({
  preview,
  previewAudience,
  previewContext,
  setPreviewAudience,
  setPreviewContext,
}: TemplateSandboxPreviewProps): React.JSX.Element {
  return (
    <section
      className="notification-toolbox"
      aria-labelledby="template-preview-tools"
    >
      <h3 id="template-preview-tools">Production-sandbox preview</h3>
      <div className="notification-form-grid">
        <label>
          Audience
          <select
            value={previewAudience}
            onChange={(event) => {
              const audience = parseAudience(event.target.value);
              if (audience) setPreviewAudience(audience);
            }}
          >
            <option value="operator">operator</option>
            <option value="customer">customer</option>
          </select>
        </label>
        <FormField htmlFor="template-preview-context" label="Context JSON">
          <Textarea
            id="template-preview-context"
            rows={3}
            value={previewContext}
            onChange={(event) => setPreviewContext(event.target.value)}
          />
        </FormField>
      </div>
      {preview ? (
        <div className="notification-preview">
          <strong>{preview.subject}</strong>
          <iframe
            title="Isolated template preview"
            sandbox=""
            referrerPolicy="no-referrer"
            srcDoc={isolateTemplatePreview(preview.html)}
          />
          <pre>{preview.plainText}</pre>
        </div>
      ) : (
        <p>No rendered preview yet.</p>
      )}
    </section>
  );
}
