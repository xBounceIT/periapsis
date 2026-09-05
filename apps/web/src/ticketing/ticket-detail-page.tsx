import {
  useInfiniteQuery,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import type {
  ActivityProjection,
  AlertCaseLinkView,
  AuditEvent,
} from "@periapsis/contracts";
import { Badge } from "@periapsis/ui/components/ui/badge";
import { Button } from "@periapsis/ui/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@periapsis/ui/components/ui/dialog";
import { Label } from "@periapsis/ui/components/ui/label";
import { Textarea } from "@periapsis/ui/components/ui/textarea";
import {
  Activity,
  ArrowDown,
  ArrowLeft,
  Braces,
  Clock3,
  ContactRound,
  FileSearch,
  GitBranch,
  Link2,
  MessageSquareText,
  RadioTower,
  RefreshCw,
  ShieldCheck,
  Tag,
  Unlink2,
  UserRound,
} from "lucide-react";
import {
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
  type FormEvent,
  type KeyboardEvent,
  type ReactNode,
} from "react";
import { Link, useNavigate, useParams } from "react-router";

import { useSession } from "../auth/session-context";
import { useTenantAuthority } from "../auth/tenant-authority-context";
import { auditReaderApi, type AuditReaderApi } from "../audit/audit-api";
import { compactAuditIdentifier, tenantAuditPermission } from "../audit/model";
import { FocusedError } from "../components/focused-error";
import { ServerDenied } from "../components/server-denied";
import {
  CustomFieldApiError,
  customFieldObjectApi,
  type CustomFieldObjectApi,
} from "../customfields/custom-field-api";
import { DynamicFieldForm } from "../customfields/dynamic-field-form";
import {
  canEditDefinition,
  customFieldValuesFromDrafts,
  safeFieldProblem,
  type CustomFieldDraft,
  type CustomFieldDrafts,
} from "../customfields/model";
import { useAlertDfirApi } from "../dfir/alert-dfir-context";
import { AlertDfirPanel } from "../dfir/alert-dfir-panel";
import { useCaseDfirApi } from "../dfir/case-dfir-context";
import { CaseDfirPanel } from "../dfir/case-dfir-panel";
import {
  alertDfirReadPermissions,
  dfirReadPermissions,
  type DfirPermission,
  type DfirReadPermission,
} from "../dfir/model";
import {
  idempotencyKeyForPayload,
  type IdempotencyReference,
} from "../lib/payload-idempotency";
import { TenantInstant } from "../lib/tenant-date-time-context";
import {
  describeTicketingError,
  TicketingApiError,
  type OperatorTicketProjection,
  type TicketKind,
  type TicketProjection,
  type VersionedTicket,
} from "../lib/ticketing-api";
import { SafeMarkdown } from "./safe-markdown";
import { caseContactApi, type CaseContactApi } from "./case-contact-api";
import { CaseContactPanel } from "./case-contact-panel";
import { TicketCommentPanel } from "./ticket-comment-panel";
import { useTicketingApi } from "./ticketing-context";
import {
  ticketMetadataApi,
  type TicketMetadataApi,
} from "./ticket-metadata-api";
import { TicketMetadataPanel } from "./ticket-metadata-panel";
import { ticketWatcherApi, type TicketWatcherApi } from "./ticket-watcher-api";
import { TicketWatcherPanel } from "./ticket-watcher-panel";
import {
  compactIdentifier,
  hasAllTicketPermissionsAtOneScope,
  hasAnyTicketPermission,
  humanizeKey,
  isAlertTicket,
  kindLabel,
  kindLabelPlural,
  priorityTone,
  severityTone,
  ticketNumber,
} from "./ticketing-model";
import { TicketOperations } from "./ticket-operations";
import { alertRelationApi, type AlertRelationApi } from "./alert-relation-api";
import { AlertRelationPanel } from "./alert-relation-panel";
import { slaAdminApi } from "../sla/sla-api";
import { TicketSlaPanel } from "../sla/ticket-sla-panel";

type DetailTab =
  | "activity"
  | "audit"
  | "comments"
  | "contacts"
  | "dfir"
  | "linked"
  | "overview";

const baseTabs = [
  { id: "overview", label: "Overview", icon: FileSearch },
  { id: "linked", label: "Linked", icon: Link2 },
  { id: "activity", label: "Activity", icon: Activity },
  { id: "comments", label: "Comments", icon: MessageSquareText },
] as const;

export function AlertDetailPage(): React.JSX.Element {
  return <TicketDetailPage kind="alert" />;
}

export function CaseDetailPage(): React.JSX.Element {
  return <TicketDetailPage kind="case" />;
}

export function TicketDetailPage({
  alertRelationApi: relationsApi = alertRelationApi,
  auditApi = auditReaderApi,
  contactApi = caseContactApi,
  customFieldApi = customFieldObjectApi,
  kind,
  metadataApi = ticketMetadataApi,
  watcherApi = ticketWatcherApi,
}: {
  alertRelationApi?: AlertRelationApi;
  auditApi?: AuditReaderApi;
  contactApi?: CaseContactApi;
  customFieldApi?: CustomFieldObjectApi;
  kind: TicketKind;
  metadataApi?: TicketMetadataApi;
  watcherApi?: TicketWatcherApi;
}): React.JSX.Element {
  const api = useTicketingApi();
  const alertDfirApi = useAlertDfirApi();
  const caseDfirApi = useCaseDfirApi();
  const { session } = useSession();
  const authority = useTenantAuthority();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const parameters = useParams();
  const resourceId =
    kind === "alert" ? parameters["alertId"] : parameters["caseId"];
  const tenantId = session.activeTenantId;
  const [tab, setTab] = useState<DetailTab>("overview");
  const queryKey = ["ticket", kind, tenantId, resourceId] as const;
  const ticketQuery = useQuery({
    enabled: Boolean(tenantId && resourceId),
    queryKey,
    queryFn: ({ signal }) =>
      api.getTicket(kind, tenantId!, resourceId!, signal),
    retry: (count, error) =>
      !(
        error instanceof TicketingApiError &&
        [403, 404].includes(error.status ?? 0)
      ) && count < 1,
  });
  const hasDfirPermission = (
    permission: DfirPermission | DfirReadPermission,
  ): boolean =>
    authority.hasPermission(permission, "assigned") ||
    authority.hasPermission(permission, "operator_team") ||
    authority.hasPermission(permission, "tenant");
  const canUseDfir =
    ticketQuery.data?.value.projection === "operator" &&
    (kind === "alert" ? alertDfirReadPermissions : dfirReadPermissions).every(
      hasDfirPermission,
    );
  const authorityReady = authority.status === "ready";
  const canReadCustomFields =
    authorityReady &&
    hasAnyTicketPermission(authority.hasPermission, "custom_field.read");
  const canManageCustomFields =
    authorityReady &&
    hasAnyTicketPermission(authority.hasPermission, "custom_field.manage");
  const canEditMetadata =
    authorityReady &&
    hasAnyTicketPermission(
      authority.hasPermission,
      kind === "alert" ? "alert.update" : "case.update",
    );
  const canReadWatchers =
    authorityReady &&
    hasAnyTicketPermission(
      authority.hasPermission,
      kind === "alert" ? "alert.read" : "case.read",
    );
  const canReadAudit =
    authorityReady && authority.hasPermission(tenantAuditPermission, "tenant");
  const canReadCaseContacts =
    kind === "case" &&
    ticketQuery.data?.value.projection === "operator" &&
    authorityReady &&
    hasAnyTicketPermission(authority.hasPermission, "case.read") &&
    authority.hasPermission("contact.read", "tenant");
  const canEditCaseContacts =
    canReadCaseContacts &&
    hasAnyTicketPermission(authority.hasPermission, "case.update");

  useEffect(() => {
    if (tab === "dfir" && !canUseDfir) setTab("overview");
    if (tab === "audit" && !canReadAudit) setTab("overview");
    if (tab === "contacts" && !canReadCaseContacts) setTab("overview");
  }, [canReadAudit, canReadCaseContacts, canUseDfir, tab]);

  if (!tenantId) return <NoTenantDetail kind={kind} />;
  if (!resourceId) return <MissingTicket kind={kind} />;
  if (
    ticketQuery.error instanceof TicketingApiError &&
    ticketQuery.error.status === 403
  ) {
    return <ServerDenied resource={`${kindLabel(kind)} detail`} />;
  }

  const ticket = ticketQuery.data;
  if (ticketQuery.isPending) {
    return <TicketDetailSkeleton kind={kind} />;
  }
  if (ticketQuery.isError || !ticket) {
    return (
      <div className="content content--narrow ticket-detail-error">
        <FocusedError
          message={describeTicketingError(
            ticketQuery.error,
            `The ${kindLabel(kind).toLowerCase()} detail could not be loaded.`,
          )}
          title={`${kindLabel(kind)} unavailable`}
        />
        <Button variant="outline" onClick={() => void ticketQuery.refetch()}>
          <RefreshCw aria-hidden="true" /> Retry detail
        </Button>
      </div>
    );
  }

  const value = ticket.value;
  const operatorTicket = isOperatorVersionedTicket(ticket) ? ticket : null;

  function commit(next: VersionedTicket<OperatorTicketProjection>): void {
    queryClient.setQueryData(queryKey, next);
    void queryClient.invalidateQueries({
      queryKey: ["tickets", kind, tenantId],
    });
    void queryClient.invalidateQueries({
      queryKey: ["ticket-activity", kind, tenantId, resourceId],
    });
  }

  async function reloadLatestTicketBoundary(): Promise<{
    etag: string;
    version: number;
  } | null> {
    const result = await ticketQuery.refetch();
    if (!result.isSuccess || !result.data) return null;
    void queryClient.invalidateQueries({
      queryKey: ["tickets", kind, tenantId],
    });
    void queryClient.invalidateQueries({
      queryKey: ["ticket-activity", kind, tenantId, resourceId],
    });
    return {
      etag: result.data.etag,
      version: result.data.value.version,
    };
  }

  async function reloadLatestTicket(): Promise<boolean> {
    return (await reloadLatestTicketBoundary()) !== null;
  }

  return (
    <div className="content ticket-detail-page">
      <Link
        className="ticket-back-link"
        to={`/${kind === "alert" ? "alerts" : "cases"}`}
      >
        <ArrowLeft aria-hidden="true" /> Back to {kindLabelPlural(kind)}
      </Link>
      <section
        className="ticket-detail-hero"
        aria-labelledby="ticket-detail-title"
      >
        <div className="ticket-detail-hero__identity">
          <p className="section-label">
            {kindLabel(kind)} / {ticketNumber(kind, value)}
          </p>
          <h1 id="ticket-detail-title">{value.title}</h1>
          <div className="ticket-detail-hero__signals">
            <span className={severityTone(value.severity)}>
              {humanizeKey(value.severity)} severity
            </span>
            <span className={priorityTone(value.priority)}>
              {humanizeKey(value.priority)} priority
            </span>
            <Badge variant="outline">
              {humanizeKey(value.workflow.stateKey)}
            </Badge>
            <Badge variant={value.customerVisible ? "secondary" : "outline"}>
              {value.customerVisible ? "Customer visible" : "Internal"}
            </Badge>
          </div>
        </div>
        <div className="ticket-detail-hero__version">
          <span>Snapshot</span>
          <strong>v{value.version}</strong>
          <small>
            Workflow {value.workflow.version} · {value.projection} projection
          </small>
        </div>
      </section>

      {operatorTicket ? (
        <TicketOperations
          kind={kind}
          ticket={operatorTicket}
          onCommitted={commit}
          onConflict={() => ticketQuery.refetch()}
          onDeleted={() => {
            queryClient.removeQueries({ exact: true, queryKey });
            void queryClient.invalidateQueries({
              queryKey: ["tickets", "alert", tenantId],
            });
            void navigate("/alerts", { replace: true });
          }}
          onEscalated={(caseId) => void navigate(`/cases/${caseId}`)}
        />
      ) : null}

      <TicketSlaPanel
        api={slaAdminApi}
        canOverride={hasAnyTicketPermission(
          authority.hasPermission,
          kind === "alert" ? "alert.sla.override" : "case.sla.override",
        )}
        canRead={hasAnyTicketPermission(
          authority.hasPermission,
          kind === "alert" ? "alert.read" : "case.read",
        )}
        csrfToken={session.csrfToken}
        expectedAudience="operator"
        kind={kind}
        objectId={resourceId}
        tenantId={tenantId}
      />

      <TicketTabs
        active={tab}
        includeAudit={canReadAudit}
        includeContacts={canReadCaseContacts}
        includeDfir={canUseDfir}
        onChange={setTab}
      />
      <section className="ticket-detail-panel" aria-live="polite">
        {tab === "overview" ? (
          <Overview
            customFields={
              operatorTicket ? (
                <TicketCustomFieldsPanel
                  api={customFieldApi}
                  canManage={canManageCustomFields}
                  canRead={canReadCustomFields}
                  csrfToken={session.csrfToken}
                  objectId={resourceId}
                  objectType={kind}
                  tenantId={tenantId}
                />
              ) : null
            }
            kind={kind}
            metadata={
              operatorTicket ? (
                <TicketMetadataPanel
                  api={metadataApi}
                  canEdit={canEditMetadata}
                  csrfToken={session.csrfToken}
                  kind={kind}
                  onReloadLatest={reloadLatestTicket}
                  sessionId={session.id}
                  tenantId={tenantId}
                  ticket={operatorTicket}
                />
              ) : null
            }
            ticket={value}
            watchers={
              operatorTicket ? (
                <TicketWatcherPanel
                  api={watcherApi}
                  authorityEpoch={JSON.stringify([
                    authority.pairKey,
                    authority.revision,
                    authority.authority?.evaluatedAt ?? null,
                  ])}
                  canEdit={canEditMetadata}
                  canRead={canReadWatchers}
                  csrfToken={session.csrfToken}
                  kind={kind}
                  onReloadLatest={reloadLatestTicketBoundary}
                  resourceId={resourceId}
                  sessionId={session.id}
                  tenantId={tenantId}
                  ticketEtag={operatorTicket.etag}
                  ticketVersion={operatorTicket.value.version}
                />
              ) : null
            }
          />
        ) : null}
        {tab === "linked" ? (
          <LinkedPanel
            alertRelation={
              kind === "alert" && operatorTicket !== null
                ? {
                    alertEtag: operatorTicket.etag,
                    alertVersion: operatorTicket.value.version,
                    api: relationsApi,
                    canManage:
                      authorityReady &&
                      hasAllTicketPermissionsAtOneScope(
                        authority.hasPermission,
                        ["alert.read", "alert.update"],
                      ),
                    onReloadLatest: reloadLatestTicketBoundary,
                    sessionId: session.id,
                  }
                : undefined
            }
            authorityEpoch={JSON.stringify([
              session.id,
              authority.pairKey,
              authority.revision,
              authority.authority?.evaluatedAt ?? null,
            ])}
            canUnlink={
              operatorTicket !== null &&
              authorityReady &&
              hasAnyTicketPermission(
                authority.hasPermission,
                "alert.escalate",
              ) &&
              hasAnyTicketPermission(authority.hasPermission, "case.update")
            }
            csrfToken={session.csrfToken}
            kind={kind}
            onChanged={() => ticketQuery.refetch()}
            tenantId={tenantId}
            resourceId={resourceId}
          />
        ) : null}
        {tab === "activity" ? (
          <ActivityPanel
            kind={kind}
            tenantId={tenantId}
            resourceId={resourceId}
          />
        ) : null}
        {tab === "audit" && canReadAudit ? (
          <TicketAuditPanel
            api={auditApi}
            kind={kind}
            resourceId={resourceId}
            tenantId={tenantId}
          />
        ) : null}
        {tab === "comments" ? (
          <TicketCommentPanel
            kind={kind}
            projection={value.projection}
            tenantId={tenantId}
            resourceId={resourceId}
          />
        ) : null}
        {tab === "contacts" && canReadCaseContacts && operatorTicket ? (
          <CaseContactPanel
            api={contactApi}
            authorityEpoch={JSON.stringify([
              session.id,
              authority.pairKey,
              authority.revision,
              authority.authority?.evaluatedAt ?? null,
            ])}
            canEdit={canEditCaseContacts}
            canRead={canReadCaseContacts}
            caseEtag={operatorTicket.etag}
            caseId={resourceId}
            caseVersion={operatorTicket.value.version}
            csrfToken={session.csrfToken}
            onReloadLatest={reloadLatestTicketBoundary}
            sessionId={session.id}
            tenantId={tenantId}
          />
        ) : null}
        {tab === "dfir" && canUseDfir && kind === "case" ? (
          <CaseDfirPanel
            api={caseDfirApi}
            caseId={resourceId}
            csrfToken={session.csrfToken}
            hasPermission={hasDfirPermission}
            tenantId={tenantId}
          />
        ) : null}
        {tab === "dfir" && canUseDfir && kind === "alert" ? (
          <AlertDfirPanel
            alertId={resourceId}
            api={alertDfirApi}
            csrfToken={session.csrfToken}
            hasPermission={hasDfirPermission}
            tenantId={tenantId}
          />
        ) : null}
      </section>
    </div>
  );
}

function TicketTabs({
  active,
  includeAudit,
  includeContacts,
  includeDfir,
  onChange,
}: {
  active: DetailTab;
  includeAudit: boolean;
  includeContacts: boolean;
  includeDfir: boolean;
  onChange: (tab: DetailTab) => void;
}): React.JSX.Element {
  const tabs: Array<{
    id: DetailTab;
    label: string;
    icon: typeof Activity;
  }> = [...baseTabs];
  if (includeContacts)
    tabs.push({ id: "contacts", label: "Contacts", icon: ContactRound });
  if (includeDfir) tabs.push({ id: "dfir", label: "DFIR", icon: RadioTower });
  if (includeAudit)
    tabs.push({ id: "audit", label: "Audit", icon: ShieldCheck });

  return (
    <div
      className="ticket-tabs"
      role="tablist"
      aria-label="Ticket detail sections"
    >
      {tabs.map(({ icon: Icon, id, label }) => (
        <button
          type="button"
          role="tab"
          aria-controls={`ticket-panel-${id}`}
          aria-selected={active === id}
          id={`ticket-tab-${id}`}
          key={id}
          onClick={() => onChange(id)}
          onKeyDown={moveTicketTabFocus}
          tabIndex={active === id ? 0 : -1}
        >
          <Icon aria-hidden="true" /> {label}
        </button>
      ))}
    </div>
  );
}

function Overview({
  customFields,
  kind,
  metadata,
  ticket,
  watchers,
}: {
  customFields?: ReactNode;
  kind: TicketKind;
  metadata?: ReactNode;
  ticket: TicketProjection;
  watchers?: ReactNode;
}): React.JSX.Element {
  const operator = ticket.projection === "operator" ? ticket : null;
  const facts: Array<[string, ReactNode]> = [
    ["Workflow", `${ticket.workflow.workflowId} · v${ticket.workflow.version}`],
    ["State", humanizeKey(ticket.workflow.stateKey)],
    ["Category", ticket.category || "Uncategorized"],
    ["Updated", <TenantInstant value={ticket.updatedAt} />],
    [
      kind === "alert" ? "Detected" : "Detection time",
      <TenantInstant
        value={
          isAlertTicket(kind, ticket) ? ticket.detectedAt : ticket.detectionTime
        }
      />,
    ],
    ["Created", <TenantInstant value={ticket.createdAt} />],
  ];
  if (operator) {
    facts.push(
      ["Team", compactIdentifier(operator.assignment.assignedTeamId)],
      ["Assignee", compactIdentifier(operator.assignment.assigneeUserId)],
      ["Claimed by", compactIdentifier(operator.assignment.claimedBy)],
      ["Classification", operator.classification || "Not classified"],
    );
  }

  return (
    <div
      id="ticket-panel-overview"
      role="tabpanel"
      aria-labelledby="ticket-tab-overview"
      className="ticket-overview"
    >
      {metadata}

      {watchers}

      <article className="ticket-narrative">
        <p className="section-label">Operational narrative</p>
        {ticket.description ? (
          <SafeMarkdown markdown={ticket.description} />
        ) : (
          <p className="ticket-muted-copy">No description was recorded.</p>
        )}
        {kind === "case" && "summary" in ticket && ticket.summary ? (
          <blockquote>{ticket.summary}</blockquote>
        ) : null}
      </article>

      <dl className="ticket-fact-grid">
        {facts.map(([label, value]) => (
          <div key={label}>
            <dt>{label}</dt>
            <dd>{value}</dd>
          </div>
        ))}
      </dl>

      <section className="ticket-tag-section">
        <div>
          <Tag aria-hidden="true" />
          <h3>Tags</h3>
        </div>
        {ticket.tags.length > 0 ? (
          <ul>
            {ticket.tags.map((tag) => (
              <li key={tag}>{tag}</li>
            ))}
          </ul>
        ) : (
          <p className="ticket-muted-copy">No tags in this projection.</p>
        )}
      </section>

      {customFields}

      {kind === "alert" &&
      operator &&
      "rawPayload" in operator &&
      operator.rawPayload ? (
        <details className="ticket-raw-payload">
          <summary>View redacted source payload</summary>
          <pre>{JSON.stringify(operator.rawPayload, null, 2)}</pre>
        </details>
      ) : null}
    </div>
  );
}

function TicketCustomFieldsPanel({
  api,
  canManage,
  canRead,
  csrfToken,
  objectId,
  objectType,
  tenantId,
}: {
  api: CustomFieldObjectApi;
  canManage: boolean;
  canRead: boolean;
  csrfToken: string;
  objectId: string;
  objectType: TicketKind;
  tenantId: string;
}): React.JSX.Element {
  const queryClient = useQueryClient();
  const queryKey = [
    "ticket-custom-fields",
    objectType,
    tenantId,
    objectId,
  ] as const;
  const query = useQuery({
    enabled: canRead,
    queryKey,
    queryFn: ({ signal }) =>
      api.get({ objectId, objectType, signal, tenantId }),
    retry: (count, error) =>
      !(
        error instanceof CustomFieldApiError &&
        [401, 403, 404].includes(error.status ?? 0)
      ) && count < 1,
  });
  const [editing, setEditing] = useState(false);
  const [drafts, setDrafts] = useState<CustomFieldDrafts>({});
  const [errors, setErrors] = useState<Readonly<Record<string, string>>>({});
  const [problem, setProblem] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const saveAttempt = useRef<IdempotencyReference["current"]>(null);
  const saveRequest = useRef<AbortController | null>(null);
  const projectionKey = query.data
    ? `${query.data.etag}:${query.data.version}`
    : "unavailable";
  const authorizationKey = `${tenantId}:${objectType}:${objectId}:${projectionKey}:${canRead}:${canManage}:${csrfToken}`;
  const authorizationEpoch = useRef({});
  const [editorKey, setEditorKey] = useState(authorizationKey);
  const editorIsCurrent = editorKey === authorizationKey;

  useLayoutEffect(() => {
    authorizationEpoch.current = {};
    saveRequest.current?.abort();
    saveRequest.current = null;
    setDrafts({});
    setEditing(false);
    setErrors({});
    setProblem(null);
    setSaving(false);
    setEditorKey(authorizationKey);
    saveAttempt.current = null;
    return () => {
      authorizationEpoch.current = {};
      saveRequest.current?.abort();
    };
  }, [authorizationKey]);

  useEffect(() => {
    if (!canRead) {
      const filters = {
        exact: true,
        queryKey: ["ticket-custom-fields", objectType, tenantId, objectId],
      } as const;
      void queryClient.cancelQueries(filters);
      queryClient.removeQueries(filters);
    }
  }, [canRead, objectId, objectType, queryClient, tenantId]);

  const startEditing = (): void => {
    if (!canManage || !editorIsCurrent || !query.data) return;
    setDrafts({ ...query.data.drafts });
    setErrors({});
    setProblem(null);
    saveAttempt.current = null;
    setEditing(true);
  };

  const cancelEditing = (): void => {
    saveRequest.current?.abort();
    saveRequest.current = null;
    setDrafts({});
    setErrors({});
    setProblem(null);
    saveAttempt.current = null;
    setEditing(false);
  };

  const reloadLatest = async (): Promise<void> => {
    cancelEditing();
    await query.refetch();
  };

  const save = async (event: FormEvent<HTMLFormElement>): Promise<void> => {
    event.preventDefault();
    const current = query.data;
    if (!canRead || !canManage || !editorIsCurrent || !current || saving)
      return;
    const validated = customFieldValuesFromDrafts(
      current.definitions,
      drafts,
      "operator",
      "update",
    );
    setErrors(validated.errors);
    setProblem(null);
    if (Object.keys(validated.errors).length > 0) return;

    const authorizationToken = authorizationEpoch.current;
    const payload = {
      expectedVersion: current.version,
      objectId,
      objectType,
      operation: "replace-ticket-custom-fields",
      tenantId,
      values: validated.values,
    };
    const idempotencyKey = idempotencyKeyForPayload(saveAttempt, payload);
    saveRequest.current?.abort();
    const controller = new AbortController();
    saveRequest.current = controller;
    setSaving(true);
    try {
      const next = await api.replace({
        csrfToken,
        current,
        idempotencyKey,
        signal: controller.signal,
        tenantId,
        values: validated.values,
      });
      if (authorizationEpoch.current !== authorizationToken) {
        return;
      }
      queryClient.setQueryData(queryKey, next);
      setDrafts({});
      setErrors({});
      setProblem(null);
      saveAttempt.current = null;
      setEditing(false);
      void queryClient.invalidateQueries({
        queryKey: ["ticket-activity", objectType, tenantId, objectId],
      });
      void queryClient.invalidateQueries({
        queryKey: ["tickets", objectType, tenantId],
      });
    } catch (error) {
      if (
        authorizationEpoch.current !== authorizationToken ||
        controller.signal.aborted
      ) {
        return;
      }
      setProblem(
        error instanceof CustomFieldApiError
          ? safeFieldProblem(error.status ?? 500)
          : safeFieldProblem(500),
      );
    } finally {
      if (authorizationEpoch.current === authorizationToken) {
        if (saveRequest.current === controller) {
          saveRequest.current = null;
          setSaving(false);
        }
      }
    }
  };

  if (!canRead) {
    return (
      <CustomFieldSection>
        <p className="ticket-muted-copy">
          Custom fields stay hidden until live read authority is available.
        </p>
      </CustomFieldSection>
    );
  }
  if (query.isPending) {
    return (
      <CustomFieldSection>
        <div
          aria-label="Loading custom fields"
          className="ticket-custom-fields__skeleton"
          role="status"
        >
          <span />
          <span />
          <span />
        </div>
      </CustomFieldSection>
    );
  }
  if (query.isError || !query.data) {
    return (
      <CustomFieldSection>
        <div className="ticket-custom-fields__problem" role="alert">
          <p>The governed custom-field projection could not be loaded.</p>
          <Button variant="outline" onClick={() => void query.refetch()}>
            <RefreshCw aria-hidden="true" /> Retry custom fields
          </Button>
        </div>
      </CustomFieldSection>
    );
  }

  const projection = query.data;
  const hasEditableField = projection.definitions.some((definition) =>
    canEditDefinition(definition, "operator", "update"),
  );
  return (
    <CustomFieldSection
      action={
        canManage && editorIsCurrent && hasEditableField && !editing ? (
          <Button size="sm" variant="outline" onClick={startEditing}>
            Edit custom fields
          </Button>
        ) : null
      }
      version={projection.version}
    >
      {projection.definitions.length === 0 ? (
        <p className="ticket-muted-copy">
          No custom fields apply to this detail view.
        </p>
      ) : editing && canManage && editorIsCurrent ? (
        <form className="ticket-custom-fields__editor" onSubmit={save}>
          <DynamicFieldForm
            audience="operator"
            baselineDrafts={projection.drafts}
            definitions={projection.definitions}
            disabled={saving}
            drafts={drafts}
            errors={errors}
            onChange={(key: string, draft: CustomFieldDraft) =>
              setDrafts((current) => ({ ...current, [key]: draft }))
            }
            phase="update"
          />
          {problem ? (
            <p className="ticket-custom-fields__problem" role="alert">
              {problem}
            </p>
          ) : null}
          <div className="ticket-custom-fields__actions">
            {problem ? (
              <Button
                type="button"
                variant="outline"
                disabled={saving}
                onClick={() => void reloadLatest()}
              >
                <RefreshCw aria-hidden="true" /> Reload latest fields
              </Button>
            ) : null}
            <Button
              type="button"
              variant="ghost"
              disabled={saving}
              onClick={cancelEditing}
            >
              Cancel
            </Button>
            <Button type="submit" disabled={saving || !canManage}>
              {saving ? "Saving…" : "Save custom fields"}
            </Button>
          </div>
        </form>
      ) : (
        <DynamicFieldForm
          audience="operator"
          definitions={projection.definitions}
          disabled
          drafts={projection.drafts}
          onChange={() => undefined}
          phase="update"
        />
      )}
    </CustomFieldSection>
  );
}

function CustomFieldSection({
  action,
  children,
  version,
}: {
  action?: ReactNode;
  children: ReactNode;
  version?: number;
}): React.JSX.Element {
  return (
    <section
      className="ticket-custom-fields"
      aria-labelledby="ticket-custom-fields-title"
    >
      <div className="ticket-custom-fields__heading">
        <span>
          <Braces aria-hidden="true" />
          <h3 id="ticket-custom-fields-title">Custom fields</h3>
        </span>
        <span className="ticket-custom-fields__controls">
          {version ? (
            <Badge variant="outline">Snapshot v{version}</Badge>
          ) : null}
          {action}
        </span>
      </div>
      {children}
    </section>
  );
}

function LinkedPanel({
  alertRelation,
  authorityEpoch,
  canUnlink,
  csrfToken,
  kind,
  onChanged,
  resourceId,
  tenantId,
}: {
  alertRelation?:
    | {
        alertEtag: string;
        alertVersion: number;
        api: AlertRelationApi;
        canManage: boolean;
        onReloadLatest: () => Promise<{
          etag: string;
          version: number;
        } | null>;
        sessionId: string;
      }
    | undefined;
  authorityEpoch: string;
  canUnlink: boolean;
  csrfToken: string;
  kind: TicketKind;
  onChanged: () => Promise<unknown>;
  resourceId: string;
  tenantId: string;
}): React.JSX.Element {
  const api = useTicketingApi();
  const query = useInfiniteQuery({
    initialPageParam: undefined as string | undefined,
    queryKey: ["ticket-links", kind, tenantId, resourceId],
    queryFn: ({ pageParam, signal }) =>
      api.listLinks(kind, tenantId, resourceId, pageParam, signal),
    getNextPageParam: (page, pages) => nextCursor(page.nextCursor, pages),
  });
  const items = query.data?.pages.flatMap((page) => page.items) ?? [];
  return (
    <div
      aria-labelledby="ticket-tab-linked"
      className="ticket-linked-workspace"
      id="ticket-panel-linked"
      role="tabpanel"
    >
      {alertRelation ? (
        <AlertRelationPanel
          alertEtag={alertRelation.alertEtag}
          alertId={resourceId}
          alertVersion={alertRelation.alertVersion}
          api={alertRelation.api}
          authorityEpoch={authorityEpoch}
          canManage={alertRelation.canManage}
          csrfToken={csrfToken}
          onReloadLatest={alertRelation.onReloadLatest}
          sessionId={alertRelation.sessionId}
          tenantId={tenantId}
        />
      ) : null}
      <section aria-labelledby="alert-case-links-title">
        <header className="ticket-linked-workspace__header">
          <p className="section-label">Governed escalation</p>
          <h2 id="alert-case-links-title">
            {kind === "alert" ? "Linked Cases" : "Linked Alerts"}
          </h2>
        </header>
        <AsyncPanel
          id="alert-case-links"
          nested
          query={query}
          emptyTitle="No governed links yet"
          emptyCopy={`This ${kindLabel(kind).toLowerCase()} remains a separate aggregate.`}
          itemCount={items.length}
        >
          <div className="ticket-linked-list">
            {items.map((link) => (
              <LinkCard
                authorityEpoch={authorityEpoch}
                canUnlink={canUnlink && link.projection === "operator"}
                csrfToken={csrfToken}
                key={link.id}
                kind={kind}
                link={link}
                onChanged={onChanged}
                tenantId={tenantId}
              />
            ))}
          </div>
        </AsyncPanel>
      </section>
    </div>
  );
}

function ActivityPanel({
  kind,
  resourceId,
  tenantId,
}: {
  kind: TicketKind;
  resourceId: string;
  tenantId: string;
}): React.JSX.Element {
  const api = useTicketingApi();
  const query = useInfiniteQuery({
    initialPageParam: undefined as string | undefined,
    queryKey: ["ticket-activity", kind, tenantId, resourceId],
    queryFn: ({ pageParam, signal }) =>
      api.listActivities(kind, tenantId, resourceId, pageParam, signal),
    getNextPageParam: (page, pages) => nextCursor(page.nextCursor, pages),
  });
  const items = query.data?.pages.flatMap((page) => page.items) ?? [];
  return (
    <AsyncPanel
      id="activity"
      query={query}
      emptyTitle="No activity is visible"
      emptyCopy="Customer-hidden events are removed before this cursor is created."
      itemCount={items.length}
    >
      <ol className="ticket-activity-rail">
        {items.map((activity, index) => (
          <ActivityItem activity={activity} index={index} key={activity.id} />
        ))}
      </ol>
    </AsyncPanel>
  );
}

function TicketAuditPanel({
  api,
  kind,
  resourceId,
  tenantId,
}: {
  api: AuditReaderApi;
  kind: TicketKind;
  resourceId: string;
  tenantId: string;
}): React.JSX.Element {
  const query = useInfiniteQuery({
    initialPageParam: undefined as number | undefined,
    queryKey: ["ticket-audit", kind, tenantId, resourceId],
    queryFn: ({ pageParam, signal }) =>
      api.listTenant({
        ...(pageParam === undefined ? {} : { afterSequence: pageParam }),
        filters: { limit: 25, resourceId, resourceType: kind },
        signal,
        tenantId,
      }),
    getNextPageParam: (page, pages) =>
      page.nextSequence !== undefined &&
      !pages
        .slice(0, -1)
        .some((candidate) => candidate.nextSequence === page.nextSequence)
        ? page.nextSequence
        : undefined,
  });
  const items = query.data?.pages.flatMap((page) => page.items) ?? [];
  return (
    <AsyncPanel
      id="audit"
      query={query}
      emptyTitle="No security audit events are visible"
      emptyCopy={`The immutable tenant audit ledger has no events for this ${kindLabel(kind).toLowerCase()} in the current authorized projection.`}
      itemCount={items.length}
    >
      <ol className="ticket-activity-rail ticket-audit-rail">
        {items.map((event) => (
          <TicketAuditItem event={event} key={event.id} />
        ))}
      </ol>
    </AsyncPanel>
  );
}

function TicketAuditItem({ event }: { event: AuditEvent }): React.JSX.Element {
  const actor =
    event.actorType === "user"
      ? compactAuditIdentifier(event.actorUserId)
      : event.actorType === "service_account"
        ? compactAuditIdentifier(event.actorServiceAccountId)
        : "System";
  return (
    <li>
      <span className="ticket-activity-rail__node" aria-hidden="true">
        {event.sequence}
      </span>
      <article>
        <header>
          <div>
            <small>{humanizeKey(event.outcome)}</small>
            <strong>{event.action}</strong>
          </div>
          <TenantInstant value={event.occurredAt} precision="second">
            <Clock3 aria-hidden="true" />{" "}
          </TenantInstant>
        </header>
        <p>
          <ShieldCheck aria-hidden="true" /> {humanizeKey(event.actorType)} ·{" "}
          {actor}
        </p>
        {event.reason ? <p>{event.reason}</p> : null}
      </article>
    </li>
  );
}

function AsyncPanel({
  children,
  emptyCopy,
  emptyTitle,
  id,
  itemCount,
  nested = false,
  query,
}: {
  children: ReactNode;
  emptyCopy: string;
  emptyTitle: string;
  id: string;
  itemCount: number;
  nested?: boolean;
  query: {
    error: unknown;
    fetchNextPage: () => Promise<unknown>;
    hasNextPage: boolean;
    isError: boolean;
    isFetchingNextPage: boolean;
    isPending: boolean;
    refetch: () => Promise<unknown>;
  };
}): React.JSX.Element {
  return (
    <div
      id={`ticket-panel-${id}`}
      role={nested ? undefined : "tabpanel"}
      aria-labelledby={nested ? undefined : `ticket-tab-${id}`}
      className="ticket-async-panel"
    >
      {query.isPending ? <TicketInlineSkeleton /> : null}
      {query.isError ? (
        <div className="ticket-inline-error">
          <FocusedError
            message={describeTicketingError(
              query.error,
              "This ticket section could not be loaded.",
            )}
          />
          <Button
            variant="outline"
            size="sm"
            onClick={() => void query.refetch()}
          >
            Retry section
          </Button>
        </div>
      ) : null}
      {!query.isPending && !query.isError && itemCount === 0 ? (
        <div className="ticket-section-empty">
          <GitBranch aria-hidden="true" />
          <h3>{emptyTitle}</h3>
          <p>{emptyCopy}</p>
        </div>
      ) : null}
      {children}
      {query.hasNextPage ? (
        <Button
          variant="outline"
          size="sm"
          onClick={() => void query.fetchNextPage()}
          disabled={query.isFetchingNextPage}
        >
          <ArrowDown aria-hidden="true" />
          {query.isFetchingNextPage ? "Loading more…" : "Load more"}
        </Button>
      ) : null}
    </div>
  );
}

function LinkCard({
  authorityEpoch,
  canUnlink,
  csrfToken,
  kind,
  link,
  onChanged,
  tenantId,
}: {
  authorityEpoch: string;
  canUnlink: boolean;
  csrfToken: string;
  kind: TicketKind;
  link: AlertCaseLinkView;
  onChanged: () => Promise<unknown>;
  tenantId: string;
}): React.JSX.Element {
  const targetId = kind === "alert" ? link.caseId : link.alertId;
  const targetKind = kind === "alert" ? "cases" : "alerts";
  return (
    <article>
      <span className="ticket-linked-list__icon">
        <Link2 aria-hidden="true" />
      </span>
      <div>
        <small>{humanizeKey(link.relationType)}</small>
        <strong>{compactIdentifier(targetId)}</strong>
        <span>
          Linked <TenantInstant value={link.linkedAt} />
        </span>
      </div>
      <div className="ticket-linked-list__actions">
        <Button asChild variant="ghost" size="sm">
          <Link to={`/${targetKind}/${targetId}`}>
            Open {kind === "alert" ? "Case" : "Alert"}
          </Link>
        </Button>
        {canUnlink ? (
          <AlertCaseUnlinkControl
            alertId={link.alertId}
            authorityEpoch={authorityEpoch}
            caseId={link.caseId}
            csrfToken={csrfToken}
            onChanged={onChanged}
            tenantId={tenantId}
          />
        ) : null}
      </div>
    </article>
  );
}

function AlertCaseUnlinkControl({
  alertId,
  authorityEpoch,
  caseId,
  csrfToken,
  onChanged,
  tenantId,
}: {
  alertId: string;
  authorityEpoch: string;
  caseId: string;
  csrfToken: string;
  onChanged: () => Promise<unknown>;
  tenantId: string;
}): React.JSX.Element {
  const api = useTicketingApi();
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);
  const [reason, setReason] = useState("");
  const [saving, setSaving] = useState(false);
  const attempt = useRef<IdempotencyReference>({ current: null });
  const request = useRef<AbortController | null>(null);
  const epoch = useRef({});
  const reasonId = `unlink-reason-${alertId}-${caseId}`;

  useLayoutEffect(() => {
    epoch.current = {};
    request.current?.abort();
    request.current = null;
    attempt.current.current = null;
    setOpen(false);
    setProblem(null);
    setReason("");
    setSaving(false);
    return () => {
      epoch.current = {};
      request.current?.abort();
    };
  }, [alertId, authorityEpoch, caseId, csrfToken, tenantId]);

  const changeOpen = (next: boolean): void => {
    if (!next) request.current?.abort();
    setOpen(next);
    setProblem(null);
    if (!next) {
      setReason("");
      setSaving(false);
      attempt.current.current = null;
    }
  };

  const submit = async (event: FormEvent<HTMLFormElement>): Promise<void> => {
    event.preventDefault();
    const normalizedReason = reason.trim();
    if (!normalizedReason || saving) return;
    request.current?.abort();
    const controller = new AbortController();
    request.current = controller;
    const authorizationToken = epoch.current;
    setProblem(null);
    setSaving(true);
    try {
      const [alert, targetCase] = await Promise.all([
        api.getTicket("alert", tenantId, alertId, controller.signal),
        api.getTicket("case", tenantId, caseId, controller.signal),
      ]);
      if (
        authorizationToken !== epoch.current ||
        alert.value.projection !== "operator" ||
        targetCase.value.projection !== "operator" ||
        alert.value.id !== alertId ||
        targetCase.value.id !== caseId
      ) {
        throw new Error("Current operator snapshots are required.");
      }
      const body = {
        caseId,
        expectedCaseVersion: targetCase.value.version,
        expectedVersion: alert.value.version,
        reason: normalizedReason,
      };
      const idempotencyKey = idempotencyKeyForPayload(attempt.current, {
        alertId,
        body,
        operation: "unlink",
        tenantId,
      });
      await api.unlinkAlertCase({
        body,
        csrfToken,
        etag: alert.etag,
        idempotencyKey,
        resourceId: alertId,
        signal: controller.signal,
        tenantId,
      });
      if (
        authorizationToken !== epoch.current ||
        request.current !== controller
      ) {
        return;
      }
      attempt.current.current = null;
      setOpen(false);
      setReason("");
      await Promise.all([
        queryClient.invalidateQueries({
          queryKey: ["ticket", "alert", tenantId, alertId],
        }),
        queryClient.invalidateQueries({
          queryKey: ["ticket", "case", tenantId, caseId],
        }),
        queryClient.invalidateQueries({
          queryKey: ["ticket-links", "alert", tenantId, alertId],
        }),
        queryClient.invalidateQueries({
          queryKey: ["ticket-links", "case", tenantId, caseId],
        }),
        queryClient.invalidateQueries({
          queryKey: ["ticket-activity", "alert", tenantId, alertId],
        }),
        queryClient.invalidateQueries({
          queryKey: ["ticket-activity", "case", tenantId, caseId],
        }),
        queryClient.invalidateQueries({
          queryKey: ["tickets", "alert", tenantId],
        }),
        queryClient.invalidateQueries({
          queryKey: ["tickets", "case", tenantId],
        }),
        queryClient.invalidateQueries({
          queryKey: ["alert-dfir", tenantId, alertId],
        }),
        queryClient.invalidateQueries({
          queryKey: ["case-dfir", tenantId, caseId],
        }),
      ]);
      await onChanged();
    } catch (error) {
      if (
        authorizationToken !== epoch.current ||
        request.current !== controller ||
        controller.signal.aborted
      ) {
        return;
      }
      setProblem(
        describeTicketingError(
          error,
          "The link could not be removed from the current governed snapshots.",
        ),
      );
    } finally {
      if (
        authorizationToken === epoch.current &&
        request.current === controller
      ) {
        request.current = null;
        setSaving(false);
      }
    }
  };

  return (
    <Dialog open={open} onOpenChange={changeOpen}>
      <DialogTrigger asChild>
        <Button size="sm" variant="outline">
          <Unlink2 aria-hidden="true" /> Unlink
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Unlink Alert from Case?</DialogTitle>
          <DialogDescription>
            The historical link and copied evidence remain immutable. This pair
            cannot be linked again after confirmation.
          </DialogDescription>
        </DialogHeader>
        <form className="ticket-unlink-form" onSubmit={submit}>
          <Label htmlFor={reasonId}>Reason</Label>
          <Textarea
            autoFocus
            disabled={saving}
            id={reasonId}
            maxLength={2000}
            onChange={(event) => {
              setReason(event.currentTarget.value);
              setProblem(null);
              attempt.current.current = null;
            }}
            placeholder="Explain why this governed relationship is no longer active"
            required
            value={reason}
          />
          {problem ? <p role="alert">{problem}</p> : null}
          <div className="ticket-unlink-form__actions">
            <Button
              disabled={saving}
              onClick={() => changeOpen(false)}
              type="button"
              variant="ghost"
            >
              Cancel
            </Button>
            <Button disabled={saving || reason.trim() === ""} type="submit">
              {saving ? "Unlinking…" : "Confirm unlink"}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function ActivityItem({
  activity,
  index,
}: {
  activity: ActivityProjection;
  index: number;
}): React.JSX.Element {
  return (
    <li>
      <span className="ticket-activity-rail__node" aria-hidden="true">
        {String(index + 1).padStart(2, "0")}
      </span>
      <article>
        <header>
          <div>
            <small>{humanizeKey(activity.kind)}</small>
            <strong>{activity.summary}</strong>
          </div>
          <TenantInstant value={activity.occurredAt}>
            <Clock3 aria-hidden="true" />{" "}
          </TenantInstant>
        </header>
        <p>
          <UserRound aria-hidden="true" /> {activity.actor.displayName}
        </p>
      </article>
    </li>
  );
}

function TicketDetailSkeleton({
  kind,
}: {
  kind: TicketKind;
}): React.JSX.Element {
  return (
    <div
      className="content ticket-detail-skeleton"
      aria-label={`Loading ${kindLabel(kind)} detail`}
    >
      <span />
      <span />
      <span />
    </div>
  );
}

function TicketInlineSkeleton(): React.JSX.Element {
  return (
    <div className="ticket-inline-skeleton" aria-label="Loading section">
      <span />
      <span />
      <span />
    </div>
  );
}

function NoTenantDetail({ kind }: { kind: TicketKind }): React.JSX.Element {
  return (
    <div className="content content--narrow">
      <section className="page-heading">
        <div>
          <p className="section-label">Tenant context required</p>
          <h1>Select a tenant first.</h1>
          <p>
            {kindLabel(kind)} detail is always resolved inside an active tenant.
          </p>
        </div>
      </section>
    </div>
  );
}

function MissingTicket({ kind }: { kind: TicketKind }): React.JSX.Element {
  return (
    <div className="content content--narrow">
      <FocusedError
        message={`The ${kindLabel(kind)} identifier is missing from this route.`}
      />
    </div>
  );
}

function nextCursor(
  cursor: string | undefined,
  pages: Array<{ nextCursor?: string }>,
): string | undefined {
  return cursor &&
    !pages.slice(0, -1).some((page) => page.nextCursor === cursor)
    ? cursor
    : undefined;
}

function isOperatorVersionedTicket(
  ticket: VersionedTicket,
): ticket is VersionedTicket<OperatorTicketProjection> {
  return ticket.value.projection === "operator";
}

function moveTicketTabFocus(event: KeyboardEvent<HTMLButtonElement>): void {
  if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
  const buttons = Array.from(
    event.currentTarget.parentElement?.querySelectorAll<HTMLButtonElement>(
      '[role="tab"]',
    ) ?? [],
  );
  const current = buttons.indexOf(event.currentTarget);
  const next =
    event.key === "Home"
      ? 0
      : event.key === "End"
        ? buttons.length - 1
        : (current + (event.key === "ArrowRight" ? 1 : -1) + buttons.length) %
          buttons.length;
  event.preventDefault();
  buttons[next]?.focus();
}
