import { Badge } from "@periapsis/ui/components/ui/badge";
import { Button } from "@periapsis/ui/components/ui/button";
import { Checkbox } from "@periapsis/ui/components/ui/checkbox";
import { Input } from "@periapsis/ui/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@periapsis/ui/components/ui/table";
import { Archive, PencilLine, Plus } from "lucide-react";
import {
  useCallback,
  useRef,
  useState,
  type FormEvent,
  type ReactNode,
} from "react";

import { FormField } from "../components/form-field";
import {
  idempotencyKeyForPayload,
  type IdempotencyReference,
} from "../lib/payload-idempotency";
import type { SlaCursorPage, VersionedSlaResource } from "./model";
import {
  SlaEmpty,
  SlaError,
  SlaInventoryHeading,
  SlaLoading,
} from "./sla-primitives";
import { useSlaInventory } from "./use-sla-inventory";

export interface SlaCatalogResource {
  archivedAt?: string;
  id: string;
  key: string;
  name?: string;
  label?: string;
  resourceVersion: number;
  tenantId: string;
  version: number;
}

export interface SlaResourceEditorProps<Draft> {
  draft: Draft;
  disabled: boolean;
  setDraft: (update: (current: Draft) => Draft) => void;
}

interface VersionedResourcePanelProps<
  Resource extends SlaCatalogResource,
  Draft,
> {
  archive: (input: {
    csrfToken: string;
    etag: string;
    id: string;
    idempotencyKey: string;
    reason: string;
    tenantId: string;
  }) => Promise<VersionedSlaResource<Resource>>;
  canManage: boolean;
  create: (input: {
    body: Draft;
    csrfToken: string;
    idempotencyKey: string;
    tenantId: string;
  }) => Promise<VersionedSlaResource<Resource>>;
  csrfToken: string;
  draftFrom: (resource?: Resource) => Draft;
  editor: (props: SlaResourceEditorProps<Draft>) => ReactNode;
  emptyDetail: string;
  eyebrow: string;
  get: (input: {
    id: string;
    signal?: AbortSignal;
    tenantId: string;
  }) => Promise<VersionedSlaResource<Resource>>;
  kindLabel: string;
  list: (input: {
    after?: string;
    includeArchived?: boolean;
    signal?: AbortSignal;
    tenantId: string;
  }) => Promise<SlaCursorPage<Resource>>;
  normalize: (draft: Draft) => Draft;
  renderSummary: (resource: Resource) => ReactNode;
  tenantId: string;
  version: (input: {
    body: Draft;
    csrfToken: string;
    etag: string;
    id: string;
    idempotencyKey: string;
    tenantId: string;
  }) => Promise<VersionedSlaResource<Resource>>;
}

export function VersionedResourcePanel<
  Resource extends SlaCatalogResource,
  Draft,
>({
  archive,
  canManage,
  create,
  csrfToken,
  draftFrom,
  editor,
  emptyDetail,
  eyebrow,
  get,
  kindLabel,
  list,
  normalize,
  renderSummary,
  tenantId,
  version,
}: VersionedResourcePanelProps<Resource, Draft>): React.JSX.Element {
  const load = useCallback(
    async (after: string | undefined, signal: AbortSignal) => {
      const page = await list({
        ...(after ? { after } : {}),
        includeArchived: true,
        signal,
        tenantId,
      });
      validateCatalogPage(page, tenantId);
      return page;
    },
    [list, tenantId],
  );
  const identity = useCallback((resource: Resource) => resource.id, []);
  const inventory = useSlaInventory(load, identity);
  const [editing, setEditing] = useState<
    VersionedSlaResource<Resource> | "new" | null
  >(null);
  const [draft, setDraftState] = useState<Draft>(() => draftFrom());
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [archiveReason, setArchiveReason] = useState("");
  const [archiveAcknowledged, setArchiveAcknowledged] = useState(false);
  const mutationAttempt = useRef<IdempotencyReference>({ current: null });
  const archiveAttempt = useRef<IdempotencyReference>({ current: null });

  function setDraft(update: (current: Draft) => Draft): void {
    setDraftState(update);
    setNotice(null);
  }

  function beginCreate(): void {
    setEditing("new");
    setDraftState(draftFrom());
    setError(null);
    setNotice(null);
    setArchiveReason("");
    setArchiveAcknowledged(false);
    mutationAttempt.current.current = null;
  }

  async function beginEdit(id: string): Promise<void> {
    setBusy(true);
    setError(null);
    try {
      const current = await get({ id, tenantId });
      validateCatalogVersioned(current, tenantId, id);
      setEditing(current);
      setDraftState(draftFrom(current.value));
      setArchiveReason("");
      setArchiveAcknowledged(false);
      setNotice(null);
      mutationAttempt.current.current = null;
      archiveAttempt.current.current = null;
    } catch (caught: unknown) {
      setError(caught);
    } finally {
      setBusy(false);
    }
  }

  async function save(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (!editing || !canManage) return;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const body = normalize(draft);
      const operation =
        editing === "new" ? `${kindLabel}.create` : `${kindLabel}.version`;
      const idempotencyKey = idempotencyKeyForPayload(mutationAttempt.current, {
        operation,
        tenantId,
        ...(editing === "new"
          ? {}
          : { id: editing.value.id, etag: editing.etag }),
        body,
      });
      const saved =
        editing === "new"
          ? await create({ body, csrfToken, idempotencyKey, tenantId })
          : await version({
              body,
              csrfToken,
              etag: editing.etag,
              id: editing.value.id,
              idempotencyKey,
              tenantId,
            });
      validateCatalogVersioned(
        saved,
        tenantId,
        editing === "new" ? undefined : editing.value.id,
      );
      if (editing === "new") {
        validateCreatedResource(saved);
      } else {
        validateVersionMutation(saved, editing);
      }
      inventory.upsert(saved.value);
      setEditing(saved);
      setDraftState(draftFrom(saved.value));
      setNotice(
        `${catalogName(saved.value)} version ${saved.value.version} is current.`,
      );
      mutationAttempt.current.current = null;
    } catch (caught: unknown) {
      setError(caught);
    } finally {
      setBusy(false);
    }
  }

  async function archiveCurrent(): Promise<void> {
    if (
      editing === null ||
      editing === "new" ||
      !canManage ||
      editing.value.archivedAt ||
      !archiveAcknowledged ||
      archiveReason.trim().length < 8
    )
      return;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const reason = archiveReason.trim();
      const idempotencyKey = idempotencyKeyForPayload(archiveAttempt.current, {
        operation: `${kindLabel}.archive`,
        tenantId,
        id: editing.value.id,
        etag: editing.etag,
        reason,
      });
      const archived = await archive({
        csrfToken,
        etag: editing.etag,
        id: editing.value.id,
        idempotencyKey,
        reason,
        tenantId,
      });
      validateCatalogVersioned(archived, tenantId, editing.value.id);
      validateArchiveMutation(archived, editing);
      inventory.upsert(archived.value);
      setEditing(archived);
      setDraftState(draftFrom(archived.value));
      setArchiveReason("");
      setArchiveAcknowledged(false);
      setNotice(
        `${catalogName(archived.value)} is archived. Existing SLA instances remain pinned to their published version.`,
      );
      archiveAttempt.current.current = null;
    } catch (caught: unknown) {
      setError(caught);
    } finally {
      setBusy(false);
    }
  }

  const existing = editing !== null && editing !== "new" ? editing : null;
  return (
    <div className="sla-panel-grid">
      <section
        className="sla-inventory"
        aria-busy={inventory.kind === "loading"}
      >
        <SlaInventoryHeading
          busy={inventory.kind === "loading"}
          count={inventory.items.length}
          eyebrow={eyebrow}
          label={`${titleCase(kindLabel)} catalog`}
          onRefresh={inventory.refresh}
        />
        {error && !editing ? (
          <SlaError
            error={error}
            fallback={`The ${kindLabel} operation could not be completed.`}
          />
        ) : null}
        {inventory.kind === "loading" ? (
          <SlaLoading label={`Loading ${kindLabel} catalog`} />
        ) : null}
        {inventory.error ? (
          <SlaError
            error={inventory.error}
            fallback={`${titleCase(kindLabel)} catalog could not be loaded.`}
          />
        ) : null}
        {inventory.kind === "ready" && inventory.items.length === 0 ? (
          <SlaEmpty
            title={`No ${kindLabel} versions`}
            detail={emptyDetail}
            action={
              canManage ? (
                <Button type="button" onClick={beginCreate}>
                  <Plus aria-hidden="true" /> Create {kindLabel}
                </Button>
              ) : undefined
            }
          />
        ) : null}
        {inventory.items.length > 0 ? (
          <div className="sla-table-wrap">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Definition</TableHead>
                  <TableHead>Version</TableHead>
                  <TableHead>State</TableHead>
                  <TableHead>
                    <span className="sr-only">Actions</span>
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {inventory.items.map((resource) => (
                  <TableRow key={resource.id}>
                    <TableCell>
                      <strong>{catalogName(resource)}</strong>
                      <code>{resource.key}</code>
                      {renderSummary(resource)}
                    </TableCell>
                    <TableCell>
                      <strong>v{resource.version}</strong>
                      <small>revision {resource.resourceVersion}</small>
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant={resource.archivedAt ? "outline" : "secondary"}
                      >
                        {resource.archivedAt ? "Archived" : "Published"}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <Button
                        type="button"
                        size="sm"
                        variant="ghost"
                        disabled={busy}
                        onClick={() => void beginEdit(resource.id)}
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
            Load more
          </Button>
        ) : null}
        {canManage && inventory.items.length > 0 ? (
          <Button type="button" variant="outline" onClick={beginCreate}>
            <Plus aria-hidden="true" /> New {kindLabel}
          </Button>
        ) : null}
      </section>

      <aside
        className="sla-editor"
        aria-label={`${titleCase(kindLabel)} version editor`}
      >
        {!editing ? (
          <SlaEmpty
            title={`Select a ${kindLabel}`}
            detail="Open a published definition to append an immutable version, or create a new lineage."
          />
        ) : (
          <form onSubmit={(event) => void save(event)}>
            <header>
              <div>
                <p className="section-label">
                  {editing === "new"
                    ? "New lineage"
                    : `Pinned version ${editing.value.version}`}
                </p>
                <h2>
                  {editing === "new"
                    ? `Create ${kindLabel}`
                    : `Version ${catalogName(editing.value)}`}
                </h2>
              </div>
              {existing ? (
                <Badge variant="outline">ETag {existing.etag}</Badge>
              ) : null}
            </header>
            {error ? (
              <SlaError
                error={error}
                fallback={`The ${kindLabel} operation could not be completed.`}
              />
            ) : null}
            {notice ? (
              <p className="sla-notice" role="status">
                {notice}
              </p>
            ) : null}
            {editor({
              draft,
              disabled:
                busy || !canManage || Boolean(existing?.value.archivedAt),
              setDraft,
            })}
            {canManage && !existing?.value.archivedAt ? (
              <div className="sla-editor__actions">
                <Button type="submit" disabled={busy}>
                  {editing === "new"
                    ? `Create ${kindLabel}`
                    : "Publish new version"}
                </Button>
              </div>
            ) : null}
            {existing && !existing.value.archivedAt && canManage ? (
              <section
                className="sla-archive-zone"
                aria-label={`Archive ${kindLabel}`}
              >
                <div>
                  <Archive aria-hidden="true" />
                  <strong>Archive lineage</strong>
                </div>
                <p>
                  Archived definitions cannot match new objects. Existing
                  instances remain pinned.
                </p>
                <FormField
                  htmlFor={`sla-${kindLabel}-archive-reason`}
                  label="Audited reason"
                >
                  <Input
                    id={`sla-${kindLabel}-archive-reason`}
                    minLength={8}
                    maxLength={1000}
                    value={archiveReason}
                    onChange={(event) => setArchiveReason(event.target.value)}
                  />
                </FormField>
                <label className="sla-archive-zone__acknowledgement">
                  <Checkbox
                    checked={archiveAcknowledged}
                    onCheckedChange={(checked) =>
                      setArchiveAcknowledged(checked === true)
                    }
                  />
                  <span>
                    I understand this removes the definition from future
                    matching.
                  </span>
                </label>
                <Button
                  type="button"
                  variant="destructive"
                  disabled={
                    busy ||
                    !archiveAcknowledged ||
                    archiveReason.trim().length < 8
                  }
                  onClick={() => void archiveCurrent()}
                >
                  Archive {kindLabel}
                </Button>
              </section>
            ) : null}
          </form>
        )}
      </aside>
    </div>
  );
}

function catalogName(resource: SlaCatalogResource): string {
  return resource.name ?? resource.label ?? resource.key;
}

function titleCase(value: string): string {
  return value.replace(/^./u, (character) => character.toUpperCase());
}

function validateCatalogPage<Resource extends SlaCatalogResource>(
  page: SlaCursorPage<Resource>,
  tenantId: string,
): void {
  if (page.items.length > 200 || (page.nextCursor?.length ?? 0) > 256) {
    throw new TypeError("The SLA catalog returned an unbounded page.");
  }
  const identities = new Set<string>();
  for (const resource of page.items) {
    validateCatalogResource(resource, tenantId);
    if (identities.has(resource.id)) {
      throw new TypeError("The SLA catalog returned duplicate identities.");
    }
    identities.add(resource.id);
  }
}

function validateCatalogVersioned<Resource extends SlaCatalogResource>(
  result: VersionedSlaResource<Resource>,
  tenantId: string,
  expectedId?: string,
): void {
  validateCatalogResource(result.value, tenantId);
  if (expectedId !== undefined && result.value.id !== expectedId) {
    throw new TypeError(
      "The SLA catalog returned a different resource identity.",
    );
  }
  validateStrongEtag(result.etag);
}

function validateCatalogResource(
  resource: SlaCatalogResource,
  tenantId: string,
): void {
  if (
    resource.tenantId !== tenantId ||
    !resource.id ||
    !resource.key ||
    !Number.isSafeInteger(resource.version) ||
    resource.version < 1 ||
    !Number.isSafeInteger(resource.resourceVersion) ||
    resource.resourceVersion < 1
  ) {
    throw new TypeError(
      "The SLA catalog returned an inconsistent resource projection.",
    );
  }
}

function validateCreatedResource<Resource extends SlaCatalogResource>(
  result: VersionedSlaResource<Resource>,
): void {
  if (
    result.value.version !== 1 ||
    result.value.resourceVersion !== 1 ||
    result.value.archivedAt !== undefined
  ) {
    throw new TypeError(
      "The SLA catalog returned an invalid initial resource version.",
    );
  }
}

function validateVersionMutation<Resource extends SlaCatalogResource>(
  result: VersionedSlaResource<Resource>,
  previous: VersionedSlaResource<Resource>,
): void {
  if (
    result.etag === previous.etag ||
    result.value.version !== previous.value.version + 1 ||
    result.value.resourceVersion <= previous.value.resourceVersion ||
    result.value.archivedAt !== undefined
  ) {
    throw new TypeError(
      "The SLA catalog returned an invalid immutable version transition.",
    );
  }
}

function validateArchiveMutation<Resource extends SlaCatalogResource>(
  result: VersionedSlaResource<Resource>,
  previous: VersionedSlaResource<Resource>,
): void {
  if (
    result.etag === previous.etag ||
    result.value.version !== previous.value.version ||
    result.value.resourceVersion <= previous.value.resourceVersion ||
    result.value.archivedAt === undefined ||
    !isRfc3339Instant(result.value.archivedAt)
  ) {
    throw new TypeError(
      "The SLA catalog returned an invalid archive transition.",
    );
  }
}

function isRfc3339Instant(value: string): boolean {
  return (
    /(?:Z|[+-]\d{2}:\d{2})$/u.test(value) && Number.isFinite(Date.parse(value))
  );
}

function validateStrongEtag(value: string): void {
  if (
    value.length < 3 ||
    value.length > 194 ||
    value.startsWith("W/") ||
    value[0] !== '"' ||
    value.at(-1) !== '"' ||
    value.slice(1, -1).includes('"') ||
    Array.from(value).some((character) => {
      const point = character.codePointAt(0);
      return point === undefined || point < 33 || point === 127;
    })
  ) {
    throw new TypeError("The SLA catalog returned a malformed strong ETag.");
  }
}
