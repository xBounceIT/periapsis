import {
  Alert,
  AlertDescription,
  AlertTitle,
} from "@periapsis/ui/components/ui/alert";
import { Badge } from "@periapsis/ui/components/ui/badge";
import { Button } from "@periapsis/ui/components/ui/button";
import { Input } from "@periapsis/ui/components/ui/input";
import { Label } from "@periapsis/ui/components/ui/label";
import type {
  AuditActorType,
  AuditChainVerification,
  AuditEvent,
  AuditJsonDocument,
  AuditOutcome,
} from "@periapsis/contracts";
import {
  CheckCircle2,
  ChevronRight,
  CircleAlert,
  FileClock,
  Fingerprint,
  Link2,
  ListFilter,
  LoaderCircle,
  RefreshCw,
  RotateCcw,
  Search,
  ShieldCheck,
  ShieldX,
} from "lucide-react";
import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type FormEvent,
} from "react";

import { FocusedError } from "../components/focused-error";
import { TenantInstant } from "../lib/tenant-date-time-context";
import {
  AuditApiError,
  auditReaderApi,
  type AuditPage,
  type AuditReaderApi,
} from "./audit-api";
import { AuditOperations } from "./audit-operations";
import type { AuditOperationsApi } from "./audit-operations-api";
import {
  AuditFilterError,
  auditInstantFromLocalValue,
  compactAuditIdentifier,
  emptyAuditFilterDraft,
  isAuditTenantId,
  normalizeAuditFilters,
  platformAuditPermission,
  tenantAuditPermission,
  type AuditFilterDraft,
  type AuditQuery,
  type AuditSurface,
} from "./model";

// oxlint-disable-next-line import/no-unassigned-import -- Vite extracts this module-owned stylesheet.
import "./audit.css";

interface SharedAuditWorkspaceProps {
  api?: AuditReaderApi;
  operationsApi?: AuditOperationsApi;
  authorizationStatus?: "loading" | "ready";
  canExport?: boolean;
  canManageRetention?: boolean;
  canRead: boolean;
  csrfToken: string;
  onForbidden?: () => void;
  onUnauthorized?: () => void;
}

export interface TenantAuditWorkspaceProps extends SharedAuditWorkspaceProps {
  tenantId: string;
  tenantLabel?: string;
}

export type PlatformAuditWorkspaceProps = SharedAuditWorkspaceProps;

export function TenantAuditWorkspace({
  api = auditReaderApi,
  operationsApi,
  authorizationStatus = "ready",
  canExport = false,
  canManageRetention = false,
  canRead,
  csrfToken,
  onForbidden,
  onUnauthorized,
  tenantId,
  tenantLabel = "Active tenant",
}: TenantAuditWorkspaceProps): React.JSX.Element {
  if (authorizationStatus === "loading") {
    return <AuditBoundary loading surface="tenant" />;
  }
  if (!isAuditTenantId(tenantId)) {
    return <AuditBoundary invalidTenant surface="tenant" />;
  }
  if (!canRead) {
    return <AuditBoundary surface="tenant" />;
  }
  return (
    <AuditWorkspace
      api={api}
      operationsApi={operationsApi}
      canExport={canExport}
      canManageRetention={canManageRetention}
      csrfToken={csrfToken}
      onForbidden={onForbidden}
      onUnauthorized={onUnauthorized}
      scope={{ kind: "tenant", tenantId }}
      scopeLabel={tenantLabel}
    />
  );
}

export function PlatformAuditWorkspace({
  api = auditReaderApi,
  operationsApi,
  authorizationStatus = "ready",
  canExport = false,
  canManageRetention = false,
  canRead,
  csrfToken,
  onForbidden,
  onUnauthorized,
}: PlatformAuditWorkspaceProps): React.JSX.Element {
  if (authorizationStatus === "loading") {
    return <AuditBoundary loading surface="platform" />;
  }
  if (!canRead) {
    return <AuditBoundary surface="platform" />;
  }
  return (
    <AuditWorkspace
      api={api}
      operationsApi={operationsApi}
      canExport={canExport}
      canManageRetention={canManageRetention}
      csrfToken={csrfToken}
      onForbidden={onForbidden}
      onUnauthorized={onUnauthorized}
      scope={{ kind: "platform" }}
      scopeLabel="Independent platform stream"
    />
  );
}

type AuditScope = { kind: "platform" } | { kind: "tenant"; tenantId: string };

interface AuditWorkspaceProps {
  api: AuditReaderApi;
  operationsApi: AuditOperationsApi | undefined;
  canExport: boolean;
  canManageRetention: boolean;
  csrfToken: string;
  onForbidden: (() => void) | undefined;
  onUnauthorized: (() => void) | undefined;
  scope: AuditScope;
  scopeLabel: string;
}

interface InventoryState {
  error: unknown;
  items: AuditEvent[];
  kind: "error" | "loading" | "ready";
  nextSequence?: number;
}

function AuditWorkspace({
  api,
  operationsApi,
  canExport,
  canManageRetention,
  csrfToken,
  onForbidden,
  onUnauthorized,
  scope,
  scopeLabel,
}: AuditWorkspaceProps): React.JSX.Element {
  const surface = scope.kind;
  const tenantId = scope.kind === "tenant" ? scope.tenantId : undefined;
  const [draft, setDraft] = useState<AuditFilterDraft>(() => ({
    ...emptyAuditFilterDraft,
  }));
  const [filters, setFilters] = useState<AuditQuery>(() =>
    normalizeAuditFilters({ ...emptyAuditFilterDraft }, surface),
  );
  const [filterError, setFilterError] = useState<string | null>(null);
  const [inventory, setInventory] = useState<InventoryState>({
    error: null,
    items: [],
    kind: "loading",
  });
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [revision, setRevision] = useState(0);
  const [loadingMore, setLoadingMore] = useState(false);
  const [verification, setVerification] =
    useState<AuditChainVerification | null>(null);
  const [verificationError, setVerificationError] = useState<unknown>(null);
  const [verifying, setVerifying] = useState(false);
  const paginationController = useRef<AbortController | null>(null);
  const verificationController = useRef<AbortController | null>(null);
  const boundaryCallbacks = useRef({ onForbidden, onUnauthorized });
  boundaryCallbacks.current = { onForbidden, onUnauthorized };

  const notifyBoundary = useCallback((error: unknown): void => {
    if (!(error instanceof AuditApiError)) return;
    if (error.status === 401) boundaryCallbacks.current.onUnauthorized?.();
    else if (error.status === 403 || error.code === "projection_mismatch") {
      boundaryCallbacks.current.onForbidden?.();
    }
  }, []);

  const readPage = useCallback(
    (afterSequence: number | undefined, signal: AbortSignal) => {
      const input = {
        ...(afterSequence === undefined ? {} : { afterSequence }),
        filters,
        signal,
      };
      return tenantId
        ? api.listTenant({ ...input, tenantId })
        : api.listPlatform(input);
    },
    [api, filters, tenantId],
  );

  useEffect(() => {
    const controller = new AbortController();
    paginationController.current?.abort();
    paginationController.current = null;
    setLoadingMore(false);
    setInventory({ error: null, items: [], kind: "loading" });
    setSelectedId(null);
    queueMicrotask(() => {
      if (controller.signal.aborted) return;
      void readPage(undefined, controller.signal).then(
        (page) => {
          if (controller.signal.aborted) return;
          setInventory({
            error: null,
            items: page.items,
            kind: "ready",
            ...(page.nextSequence === undefined
              ? {}
              : { nextSequence: page.nextSequence }),
          });
          setSelectedId(page.items[0]?.id ?? null);
        },
        (error: unknown) => {
          if (!controller.signal.aborted) {
            notifyBoundary(error);
            setInventory({ error, items: [], kind: "error" });
          }
        },
      );
    });
    return () => controller.abort();
  }, [notifyBoundary, readPage, revision]);

  useEffect(
    () => () => {
      paginationController.current?.abort();
      verificationController.current?.abort();
    },
    [],
  );

  const selected = useMemo(
    () => inventory.items.find((event) => event.id === selectedId) ?? null,
    [inventory.items, selectedId],
  );

  function applyFilters(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault();
    try {
      const normalized = normalizeAuditFilters(
        {
          ...draft,
          occurredBefore: auditInstantFromLocalValue(draft.occurredBefore),
          occurredFrom: auditInstantFromLocalValue(draft.occurredFrom),
        },
        surface,
      );
      setFilterError(null);
      setFilters(normalized);
    } catch (error: unknown) {
      setFilterError(
        safeAuditError(error, "Review the bounded audit filters."),
      );
    }
  }

  function clearFilters(): void {
    const cleared = { ...emptyAuditFilterDraft };
    setDraft(cleared);
    setFilterError(null);
    setFilters(normalizeAuditFilters(cleared, surface));
  }

  async function loadMore(): Promise<void> {
    const afterSequence = inventory.nextSequence;
    if (afterSequence === undefined || loadingMore) return;
    const controller = new AbortController();
    paginationController.current?.abort();
    paginationController.current = controller;
    setLoadingMore(true);
    try {
      const page = await readPage(afterSequence, controller.signal);
      if (controller.signal.aborted) return;
      setInventory((current) => appendPage(current, page, afterSequence));
    } catch (error: unknown) {
      if (!controller.signal.aborted) {
        notifyBoundary(error);
        setInventory((current) => ({ ...current, error }));
      }
    } finally {
      if (
        !controller.signal.aborted &&
        paginationController.current === controller
      ) {
        paginationController.current = null;
        setLoadingMore(false);
      }
    }
  }

  async function verifyChain(): Promise<void> {
    if (verifying) return;
    const controller = new AbortController();
    verificationController.current?.abort();
    verificationController.current = controller;
    setVerification(null);
    setVerificationError(null);
    setVerifying(true);
    try {
      const result = tenantId
        ? await api.verifyTenant({
            csrfToken,
            signal: controller.signal,
            tenantId,
          })
        : await api.verifyPlatform({ csrfToken, signal: controller.signal });
      if (!controller.signal.aborted) setVerification(result);
    } catch (error: unknown) {
      if (!controller.signal.aborted) {
        notifyBoundary(error);
        setVerificationError(error);
      }
    } finally {
      if (
        !controller.signal.aborted &&
        verificationController.current === controller
      ) {
        verificationController.current = null;
        setVerifying(false);
      }
    }
  }

  const permission =
    surface === "tenant" ? tenantAuditPermission : platformAuditPermission;

  return (
    <section
      className="audit-workspace"
      aria-labelledby={`${surface}-audit-title`}
    >
      <header className="audit-heading">
        <div className="audit-heading__chain" aria-hidden="true">
          <span />
          <Link2 />
          <i />
        </div>
        <div className="audit-heading__copy">
          <p className="section-label">Integrity ledger / ordered evidence</p>
          <h1 id={`${surface}-audit-title`}>
            {surface === "tenant"
              ? "Tenant audit ledger"
              : "Platform audit ledger"}
          </h1>
          <p>
            Inspect the append-only, redacted event sequence and verify its
            tamper-evident chain without retrieving protected source payloads.
          </p>
        </div>
        <div className="audit-heading__actions">
          <div className="audit-scope-chip">
            <span>
              {surface === "tenant" ? "Tenant boundary" : "Platform boundary"}
            </span>
            <strong>{scopeLabel}</strong>
            <Badge variant="outline">{permission}</Badge>
          </div>
          <Button
            type="button"
            variant="outline"
            onClick={() => void verifyChain()}
            disabled={verifying}
          >
            {verifying ? (
              <LoaderCircle className="is-spinning" aria-hidden="true" />
            ) : (
              <ShieldCheck aria-hidden="true" />
            )}
            {verifying ? "Verifying chain" : "Verify chain"}
          </Button>
        </div>
      </header>

      <div className="audit-trust-line" aria-label="Audit reader safeguards">
        <span>
          <Fingerprint aria-hidden="true" /> Redacted projections only
        </span>
        <span>
          <FileClock aria-hidden="true" /> Stable sequence cursor
        </span>
        <span>
          <ShieldCheck aria-hidden="true" /> Reads and verification are
          self-audited
        </span>
      </div>

      <AuditOperations
        {...(operationsApi ? { api: operationsApi } : {})}
        canExport={canExport}
        canManageRetention={canManageRetention}
        csrfToken={csrfToken}
        filters={filters}
        onBoundaryError={notifyBoundary}
        scope={scope}
      />

      <VerificationNotice error={verificationError} result={verification} />

      <div className="audit-console">
        <AuditFilters
          draft={draft}
          error={filterError}
          onApply={applyFilters}
          onChange={setDraft}
          onClear={clearFilters}
          surface={surface}
        />

        <section
          className="audit-ledger"
          aria-labelledby="audit-events-title"
          aria-busy={inventory.kind === "loading"}
        >
          <div className="audit-ledger__toolbar">
            <div>
              <p className="section-label">Forward-only sequence</p>
              <h2 id="audit-events-title">Recorded events</h2>
              <p aria-live="polite">
                {inventory.kind === "ready"
                  ? `${inventory.items.length} event${inventory.items.length === 1 ? "" : "s"} loaded`
                  : "Loading the protected audit stream"}
              </p>
            </div>
            <Button
              type="button"
              variant="outline"
              onClick={() => setRevision((value) => value + 1)}
              disabled={inventory.kind === "loading"}
            >
              <RefreshCw aria-hidden="true" /> Refresh
            </Button>
          </div>

          {inventory.kind === "loading" ? (
            <AuditLoading />
          ) : inventory.kind === "error" ? (
            <div className="audit-ledger__state">
              <FocusedError
                message={safeAuditError(
                  inventory.error,
                  "The protected audit stream could not be loaded.",
                )}
                title="Audit stream unavailable"
              />
              <Button
                type="button"
                variant="outline"
                onClick={() => setRevision((value) => value + 1)}
              >
                Try again
              </Button>
            </div>
          ) : inventory.items.length === 0 ? (
            <div className="audit-ledger__empty">
              <ListFilter aria-hidden="true" />
              <strong>No events match these filters</strong>
              <p>
                Broaden the time range or clear exact identifiers. The reader
                never searches before, after, or metadata documents.
              </p>
            </div>
          ) : (
            <>
              {inventory.error ? (
                <FocusedError
                  autoFocus={false}
                  message={safeAuditError(
                    inventory.error,
                    "The next audit page could not be loaded.",
                  )}
                  title="Pagination stopped"
                />
              ) : null}
              <div className="audit-investigation">
                <AuditEventList
                  items={inventory.items}
                  onSelect={setSelectedId}
                  selectedId={selectedId}
                />
                <AuditEventDetail event={selected} />
              </div>
              {inventory.nextSequence !== undefined ? (
                <div className="audit-load-more">
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => void loadMore()}
                    disabled={loadingMore}
                  >
                    {loadingMore ? (
                      <LoaderCircle
                        className="is-spinning"
                        aria-hidden="true"
                      />
                    ) : (
                      <ChevronRight aria-hidden="true" />
                    )}
                    {loadingMore ? "Loading next page" : "Load next sequence"}
                  </Button>
                </div>
              ) : null}
            </>
          )}
        </section>
      </div>
    </section>
  );
}

function AuditFilters({
  draft,
  error,
  onApply,
  onChange,
  onClear,
  surface,
}: {
  draft: AuditFilterDraft;
  error: string | null;
  onApply: (event: FormEvent<HTMLFormElement>) => void;
  onChange: (draft: AuditFilterDraft) => void;
  onClear: () => void;
  surface: AuditSurface;
}): React.JSX.Element {
  function update<Key extends keyof AuditFilterDraft>(
    key: Key,
    value: AuditFilterDraft[Key],
  ): void {
    onChange({ ...draft, [key]: value });
  }

  return (
    <aside className="audit-filter-panel" aria-labelledby="audit-filter-title">
      <div className="audit-filter-panel__heading">
        <ListFilter aria-hidden="true" />
        <div>
          <p className="section-label">Bounded query</p>
          <h2 id="audit-filter-title">Filter ledger</h2>
        </div>
      </div>
      <form onSubmit={onApply} noValidate>
        <div className="audit-field audit-field--search">
          <Label htmlFor="audit-search">Search allowed fields</Label>
          <span className="audit-search-input">
            <Search aria-hidden="true" />
            <Input
              id="audit-search"
              aria-describedby="audit-search-help"
              value={draft.search}
              maxLength={256}
              onChange={(event) => update("search", event.currentTarget.value)}
              placeholder="Action, resource, reason"
            />
          </span>
          <small id="audit-search-help">
            Never searches change documents or metadata.
          </small>
        </div>

        <div className="audit-filter-grid">
          <Label className="audit-field">
            <span>Action prefix</span>
            <Input
              value={draft.actionPrefix}
              maxLength={128}
              onChange={(event) =>
                update("actionPrefix", event.currentTarget.value)
              }
              placeholder="case.transition"
            />
          </Label>
          <Label className="audit-field">
            <span>Resource type</span>
            <Input
              value={draft.resourceType}
              maxLength={128}
              onChange={(event) =>
                update("resourceType", event.currentTarget.value)
              }
              placeholder="case"
            />
          </Label>
          <Label className="audit-field">
            <span>Actor type</span>
            <select
              value={draft.actorType}
              onChange={(event) =>
                update(
                  "actorType",
                  parseActorTypeInput(event.currentTarget.value),
                )
              }
            >
              <option value="">Any actor</option>
              <option value="user">User</option>
              <option value="service_account">Service account</option>
              <option value="system">System</option>
            </select>
          </Label>
          <Label className="audit-field">
            <span>Outcome</span>
            <select
              value={draft.outcome}
              onChange={(event) =>
                update("outcome", parseOutcomeInput(event.currentTarget.value))
              }
            >
              <option value="">Any outcome</option>
              <option value="success">Success</option>
              <option value="failure">Failure</option>
              <option value="denied">Denied</option>
            </select>
          </Label>
          <Label className="audit-field">
            <span>Occurred from</span>
            <Input
              type="datetime-local"
              value={draft.occurredFrom}
              onChange={(event) =>
                update("occurredFrom", event.currentTarget.value)
              }
            />
          </Label>
          <Label className="audit-field">
            <span>Occurred before</span>
            <Input
              type="datetime-local"
              value={draft.occurredBefore}
              onChange={(event) =>
                update("occurredBefore", event.currentTarget.value)
              }
            />
          </Label>
          <Label className="audit-field">
            <span>Page size</span>
            <select
              value={draft.limit}
              onChange={(event) =>
                update("limit", Number(event.currentTarget.value))
              }
            >
              <option value={25}>25 events</option>
              <option value={50}>50 events</option>
              <option value={100}>100 events</option>
            </select>
          </Label>
        </div>

        <details className="audit-exact-filters">
          <summary>Exact identifiers</summary>
          <div className="audit-filter-grid">
            <ExactIdentifierField
              label="Actor user ID"
              value={draft.actorUserId}
              onChange={(value) => update("actorUserId", value)}
            />
            {surface === "tenant" ? (
              <ExactIdentifierField
                label="Actor service-account ID"
                value={draft.actorServiceAccountId}
                onChange={(value) => update("actorServiceAccountId", value)}
              />
            ) : null}
            <ExactIdentifierField
              label="Resource ID"
              value={draft.resourceId}
              onChange={(value) => update("resourceId", value)}
            />
            <ExactIdentifierField
              label="Request ID"
              value={draft.requestId}
              onChange={(value) => update("requestId", value)}
            />
            <ExactIdentifierField
              label="Correlation ID"
              value={draft.correlationId}
              onChange={(value) => update("correlationId", value)}
            />
          </div>
        </details>

        {error ? (
          <Alert variant="destructive">
            <CircleAlert aria-hidden="true" />
            <AlertTitle>Review filters</AlertTitle>
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        ) : null}

        <div className="audit-filter-actions">
          <Button type="button" variant="ghost" onClick={onClear}>
            <RotateCcw aria-hidden="true" /> Clear
          </Button>
          <Button type="submit">
            <ListFilter aria-hidden="true" /> Apply filters
          </Button>
        </div>
      </form>
    </aside>
  );
}

function ExactIdentifierField({
  label,
  onChange,
  value,
}: {
  label: string;
  onChange: (value: string) => void;
  value: string;
}): React.JSX.Element {
  return (
    <Label className="audit-field">
      <span>{label}</span>
      <Input
        value={value}
        maxLength={36}
        onChange={(event) => onChange(event.currentTarget.value)}
        placeholder="00000000-0000-7000-8000-000000000000"
      />
    </Label>
  );
}

function AuditEventList({
  items,
  onSelect,
  selectedId,
}: {
  items: AuditEvent[];
  onSelect: (id: string) => void;
  selectedId: string | null;
}): React.JSX.Element {
  return (
    <ol className="audit-sequence" aria-label="Audit events in sequence order">
      {items.map((event) => (
        <li key={event.id}>
          <button
            type="button"
            className="audit-event"
            aria-current={selectedId === event.id ? "true" : undefined}
            aria-label={`Inspect sequence ${event.sequence}: ${event.action}`}
            onClick={() => onSelect(event.id)}
          >
            <span className="audit-event__node" aria-hidden="true" />
            <span className="audit-event__sequence">SEQ {event.sequence}</span>
            <strong>{event.action}</strong>
            <span className="audit-event__resource">
              {event.resourceType}
              {event.resourceId
                ? ` / ${compactAuditIdentifier(event.resourceId)}`
                : ""}
            </span>
            <span className="audit-event__footer">
              <OutcomeBadge outcome={event.outcome} />
              <TenantInstant value={event.occurredAt} precision="second" />
              <span>{actorLabel(event)}</span>
            </span>
          </button>
        </li>
      ))}
    </ol>
  );
}

function AuditEventDetail({
  event,
}: {
  event: AuditEvent | null;
}): React.JSX.Element {
  if (!event) {
    return (
      <aside className="audit-detail audit-detail--empty">
        <Fingerprint aria-hidden="true" />
        <strong>Select a sequence entry</strong>
        <p>Its redacted change documents and hash link will appear here.</p>
      </aside>
    );
  }

  return (
    <aside className="audit-detail" aria-labelledby="audit-detail-title">
      <header>
        <div>
          <p className="section-label">Sequence {event.sequence}</p>
          <h2 id="audit-detail-title">{event.action}</h2>
        </div>
        <OutcomeBadge outcome={event.outcome} />
      </header>

      {event.reason ? (
        <p className="audit-detail__reason">{event.reason}</p>
      ) : null}

      <dl className="audit-detail__facts">
        <DetailFact
          label="Occurred"
          value={<TenantInstant value={event.occurredAt} precision="second" />}
        />
        <DetailFact label="Actor" value={actorLabel(event)} />
        <DetailFact
          label="Resource"
          value={`${event.resourceType}${event.resourceId ? ` / ${event.resourceId}` : ""}`}
        />
        <DetailFact label="Request" value={event.requestId ?? "Not recorded"} />
        <DetailFact
          label="Correlation"
          value={event.correlationId ?? "Not recorded"}
        />
        <DetailFact
          label="Authentication"
          value={event.authenticationMethod ?? "Not recorded"}
        />
      </dl>

      <section className="audit-hash-link" aria-labelledby="audit-hash-title">
        <div>
          <Link2 aria-hidden="true" />
          <h3 id="audit-hash-title">Hash link</h3>
        </div>
        <code>
          <span>Previous</span>
          {event.previousHash}
        </code>
        <code>
          <span>Event</span>
          {event.eventHash}
        </code>
      </section>

      <section
        className="audit-documents"
        aria-labelledby="audit-documents-title"
      >
        <div className="audit-documents__heading">
          <h3 id="audit-documents-title">Redacted documents</h3>
          <Badge variant="outline">Server allowlist</Badge>
        </div>
        <AuditDocument label="Before" value={event.before} />
        <AuditDocument label="After" value={event.after} />
        <AuditDocument label="Metadata" value={event.metadata} />
      </section>

      {(event.ipAddress || event.userAgent || event.impersonatedByUserId) && (
        <details className="audit-request-context">
          <summary>Request context</summary>
          <dl>
            <DetailFact
              label="IP address"
              value={event.ipAddress ?? "Not recorded"}
            />
            <DetailFact
              label="User agent"
              value={event.userAgent ?? "Not recorded"}
            />
            <DetailFact
              label="Impersonated by"
              value={event.impersonatedByUserId ?? "Not recorded"}
            />
          </dl>
        </details>
      )}
    </aside>
  );
}

function AuditDocument({
  label,
  value,
}: {
  label: string;
  value: AuditJsonDocument;
}): React.JSX.Element {
  return (
    <details className="audit-document" open={label === "After"}>
      <summary>{label}</summary>
      <pre>{stableJson(value)}</pre>
    </details>
  );
}

function DetailFact({
  label,
  value,
}: {
  label: string;
  value: React.ReactNode;
}): React.JSX.Element {
  return (
    <div>
      <dt>{label}</dt>
      <dd>{value}</dd>
    </div>
  );
}

function VerificationNotice({
  error,
  result,
}: {
  error: unknown;
  result: AuditChainVerification | null;
}): React.JSX.Element | null {
  if (error) {
    return (
      <FocusedError
        message={safeAuditError(
          error,
          "The audit chain could not be verified.",
        )}
        title="Chain verification unavailable"
      />
    );
  }
  if (!result) return null;
  if (!result.valid) {
    return (
      <Alert variant="destructive" className="audit-verification">
        <CircleAlert aria-hidden="true" />
        <AlertTitle>Audit chain did not verify</AlertTitle>
        <AlertDescription>
          {result.firstInvalidSequence
            ? `The first invalid link is sequence ${result.firstInvalidSequence}.`
            : "The stored chain head does not match the verified sequence."}{" "}
          Checked {result.eventCount} events at{" "}
          <TenantInstant value={result.verifiedAt} precision="second" />.
        </AlertDescription>
      </Alert>
    );
  }
  return (
    <Alert className="audit-verification audit-verification--valid">
      <CheckCircle2 aria-hidden="true" />
      <AlertTitle>Audit chain verified</AlertTitle>
      <AlertDescription>
        {result.eventCount} events through sequence {result.lastSequence}{" "}
        matched the stored head at{" "}
        <TenantInstant value={result.verifiedAt} precision="second" />.
      </AlertDescription>
    </Alert>
  );
}

function OutcomeBadge({
  outcome,
}: {
  outcome: AuditOutcome;
}): React.JSX.Element {
  return (
    <Badge
      variant={outcome === "denied" ? "destructive" : "outline"}
      className={`audit-outcome audit-outcome--${outcome}`}
    >
      {outcome}
    </Badge>
  );
}

function AuditLoading(): React.JSX.Element {
  return (
    <div className="audit-ledger__loading" role="status">
      <LoaderCircle className="is-spinning" aria-hidden="true" />
      <span>Loading redacted events</span>
    </div>
  );
}

function AuditBoundary({
  invalidTenant = false,
  loading = false,
  surface,
}: {
  invalidTenant?: boolean;
  loading?: boolean;
  surface: AuditSurface;
}): React.JSX.Element {
  const permission =
    surface === "tenant" ? tenantAuditPermission : platformAuditPermission;
  return (
    <section className="audit-boundary" aria-labelledby="audit-boundary-title">
      {loading ? (
        <LoaderCircle className="is-spinning" aria-hidden="true" />
      ) : (
        <ShieldX aria-hidden="true" />
      )}
      <p className="section-label">Protected integrity ledger</p>
      <h1 id="audit-boundary-title">
        {loading
          ? "Checking audit authority"
          : invalidTenant
            ? "Tenant context required"
            : "Audit authority required"}
      </h1>
      <p>
        {loading
          ? "Waiting for the live session and permission projection before requesting audit data."
          : invalidTenant
            ? "Choose a live tenant before opening its audit stream."
            : `This route is hidden without ${permission}. The API revalidates the live session and permission on every read and verification.`}
      </p>
    </section>
  );
}

function actorLabel(event: AuditEvent): string {
  switch (event.actorType) {
    case "user":
      return `User ${compactAuditIdentifier(event.actorUserId)}`;
    case "service_account":
      return event.actorServiceAccountId
        ? `Service account ${compactAuditIdentifier(event.actorServiceAccountId)}`
        : "Platform service actor";
    case "system":
      return "System";
    default:
      return "Unknown actor";
  }
}

function appendPage(
  current: InventoryState,
  page: AuditPage,
  afterSequence: number,
): InventoryState {
  if (current.nextSequence !== afterSequence) return current;
  const identifiers = new Set(current.items.map((event) => event.id));
  const previous = current.items.at(-1);
  const next = page.items[0];
  const repeatedEvent = page.items.some((event) => identifiers.has(event.id));
  const brokenAdjacentLink =
    previous !== undefined &&
    next !== undefined &&
    next.sequence === previous.sequence + 1 &&
    next.previousHash !== previous.eventHash;
  if (repeatedEvent || brokenAdjacentLink) {
    const { nextSequence: _nextSequence, ...withoutCursor } = current;
    return {
      ...withoutCursor,
      error: new AuditApiError(
        repeatedEvent
          ? "The audit cursor repeated an event and pagination was stopped."
          : "The audit cursor returned a broken adjacent hash link and pagination was stopped.",
        undefined,
        "projection_mismatch",
      ),
    };
  }
  return {
    error: null,
    items: [...current.items, ...page.items],
    kind: "ready",
    ...(page.nextSequence === undefined
      ? {}
      : { nextSequence: page.nextSequence }),
  };
}

function stableJson(value: AuditJsonDocument): string {
  return JSON.stringify(sortJson(value), null, 2);
}

function sortJson(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortJson);
  if (!isRecord(value)) return value;
  return Object.fromEntries(
    Object.keys(value)
      .toSorted((left, right) => (left < right ? -1 : left > right ? 1 : 0))
      .map((key) => [key, sortJson(value[key])]),
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function safeAuditError(value: unknown, fallback: string): string {
  return value instanceof AuditApiError || value instanceof AuditFilterError
    ? value.message
    : fallback;
}

function parseActorTypeInput(value: string): "" | AuditActorType {
  return value === "user" || value === "service_account" || value === "system"
    ? value
    : "";
}

function parseOutcomeInput(value: string): "" | AuditOutcome {
  return value === "success" || value === "failure" || value === "denied"
    ? value
    : "";
}
