import type {
  AlertCustomerProjection,
  CaseCustomerProjection,
  CustomerActivity,
  CustomerPortalAttachment,
  CustomerPortalContact,
  CustomerPortalPreparedAttachmentDownload,
} from "@periapsis/contracts";
import { Badge } from "@periapsis/ui/components/ui/badge";
import { Button } from "@periapsis/ui/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@periapsis/ui/components/ui/card";
import { Input } from "@periapsis/ui/components/ui/input";
import { Label } from "@periapsis/ui/components/ui/label";
import { Textarea } from "@periapsis/ui/components/ui/textarea";
import {
  useInfiniteQuery,
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import {
  Activity,
  BellRing,
  BriefcaseBusiness,
  CalendarClock,
  ChevronLeft,
  CircleUserRound,
  Download,
  LoaderCircle,
  MessageSquareText,
  Paperclip,
  RefreshCw,
  Search,
  ShieldCheck,
  ShieldX,
} from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { useSearchParams } from "react-router";
import {
  formatNotificationWindows,
  parseNotificationWindows,
  saveCustomerPortalExport,
} from "./customer-portal-page-model";

import { useSession } from "../auth/session-context";
import { useTenantAuthority } from "../auth/tenant-authority-context";
import { FocusedError } from "../components/focused-error";
import {
  ContactApiError,
  contactPortalApi,
  type ContactPortalApi,
  type Versioned,
} from "../contacts/contact-api";
import {
  idempotencyKeyForPayload,
  type IdempotencyReference,
} from "../lib/payload-idempotency";
import { slaAdminApi } from "../sla/sla-api";
import { TicketSlaPanel } from "../sla/ticket-sla-panel";
import { SafeMarkdown } from "../ticketing/safe-markdown";
import { PortalCommentPanel } from "./portal-comment-panel";

export { customerPortalRouteDescriptor } from "./model";

// oxlint-disable-next-line import/no-unassigned-import -- Module-local customer portal language.
import "./customer-portal.css";

type PortalKind = "alert" | "case";
type PortalTicket = AlertCustomerProjection | CaseCustomerProjection;

interface CustomerPortalPageProps {
  api?: ContactPortalApi;
}

export function CustomerPortalPage({
  api = contactPortalApi,
}: CustomerPortalPageProps): React.JSX.Element {
  const { session } = useSession();
  const authority = useTenantAuthority();
  const tenantId = session.activeTenantId;
  const canReadAlerts = authority.hasPermission("portal.alert.read", "own");
  const canReadCases = authority.hasPermission("portal.case.read", "own");
  const canComment = authority.hasPermission("portal.comment.public", "own");
  const canReadAttachments = authority.hasPermission(
    "portal.attachment.read",
    "own",
  );
  const canManagePreferences = authority.hasPermission(
    "portal.contact.preference.manage",
    "own",
  );

  if (authority.status === "loading") {
    return <PortalBoundary loading />;
  }
  if (
    !tenantId ||
    authority.status !== "ready" ||
    (!canReadAlerts && !canReadCases && !canManagePreferences)
  ) {
    return <PortalBoundary />;
  }

  return (
    <div className="content customer-portal">
      <CustomerPortalWorkspace
        api={api}
        csrfToken={session.csrfToken}
        tenantId={tenantId}
        permissions={{
          canComment: canComment,
          canManagePreferences: canManagePreferences,
          canReadAttachments: canReadAttachments,
          canReadAlerts: canReadAlerts,
          canReadCases: canReadCases,
        }}
      />
    </div>
  );
}

interface CustomerPortalWorkspaceProps {
  api: ContactPortalApi;
  permissions: {
    canComment: boolean;
    canManagePreferences: boolean;
    canReadAttachments: boolean;
    canReadAlerts: boolean;
    canReadCases: boolean;
  };
  csrfToken: string;
  tenantId: string;
}

export function CustomerPortalWorkspace({
  api,
  permissions,
  csrfToken,
  tenantId,
}: CustomerPortalWorkspaceProps): React.JSX.Element {
  const {
    canComment,
    canManagePreferences,
    canReadAttachments,
    canReadAlerts,
    canReadCases,
  } = permissions;
  const [searchParams, setSearchParams] = useSearchParams();
  const requestedKind = searchParams.get("kind");
  const kind = preferredPortalKind(requestedKind, canReadAlerts, canReadCases);
  const requestedTicketId = searchParams.get("ticket");
  const selectedTicketId =
    requestedTicketId && uuidV7Pattern.test(requestedTicketId)
      ? requestedTicketId
      : null;
  const canCommentOnSelectedKind =
    canComment && (kind === "alert" ? canReadAlerts : canReadCases);
  const [view, setView] = useState<"incidents" | "preferences">(
    canReadAlerts || canReadCases ? "incidents" : "preferences",
  );
  const contact = useQuery({
    enabled: canManagePreferences,
    queryKey: ["customer-portal-contact", tenantId],
    queryFn: ({ signal }) => api.getPortalContact({ signal, tenantId }),
  });

  function chooseKind(next: PortalKind): void {
    const nextSearch = new URLSearchParams(searchParams);
    nextSearch.set("kind", next);
    nextSearch.delete("ticket");
    setSearchParams(nextSearch, { replace: true });
  }

  return (
    <>
      <header className="customer-portal__heading">
        <div className="customer-portal__mark" aria-hidden="true">
          <span />
          <ShieldCheck />
        </div>
        <div>
          <p className="section-label">Customer incident channel</p>
          <h1>Your incident workspace</h1>
          <p>
            This view contains only incidents explicitly shared with your exact
            customer contact. Operator notes, assignments and private activity
            are structurally absent.
          </p>
        </div>
        <div className="customer-portal__identity">
          <CircleUserRound aria-hidden="true" />
          <span>
            <small>Verified contact</small>
            <strong>
              {contact.data
                ? `${contact.data.value.firstName} ${contact.data.value.lastName}`
                : "Tenant-scoped session"}
            </strong>
          </span>
        </div>
      </header>

      <PortalViewSwitch
        canManagePreferences={canManagePreferences}
        canReadAlerts={canReadAlerts}
        canReadCases={canReadCases}
        setView={setView}
        view={view}
      />

      {view === "incidents" ? (
        selectedTicketId ? (
          <PortalTicketDetail
            api={api}
            canComment={canCommentOnSelectedKind}
            canExport={canCommentOnSelectedKind}
            canReadAttachments={canReadAttachments}
            csrfToken={csrfToken}
            kind={kind}
            resourceId={selectedTicketId}
            tenantId={tenantId}
            onBack={() => {
              const nextSearch = new URLSearchParams(searchParams);
              nextSearch.delete("ticket");
              setSearchParams(nextSearch, { replace: true });
            }}
          />
        ) : (
          <PortalIncidentInventory
            api={api}
            canReadAlerts={canReadAlerts}
            canReadCases={canReadCases}
            kind={kind}
            tenantId={tenantId}
            onKindChange={chooseKind}
            onSelect={(ticketId) => {
              const nextSearch = new URLSearchParams(searchParams);
              nextSearch.set("kind", kind);
              nextSearch.set("ticket", ticketId);
              setSearchParams(nextSearch);
            }}
          />
        )
      ) : canManagePreferences ? (
        <PortalPreferences
          api={api}
          contact={contact.data}
          csrfToken={csrfToken}
          error={contact.error}
          loading={contact.isPending}
          tenantId={tenantId}
        />
      ) : null}
    </>
  );
}

function PortalIncidentInventory({
  api,
  canReadAlerts,
  canReadCases,
  kind,
  onKindChange,
  onSelect,
  tenantId,
}: {
  api: ContactPortalApi;
  canReadAlerts: boolean;
  canReadCases: boolean;
  kind: PortalKind;
  onKindChange: (kind: PortalKind) => void;
  onSelect: (ticketId: string) => void;
  tenantId: string;
}): React.JSX.Element {
  const [search, setSearch] = useState("");
  const tickets = useInfiniteQuery({
    queryKey: ["customer-portal-tickets", tenantId, kind, search],
    initialPageParam: undefined as string | undefined,
    queryFn: ({ pageParam, signal }) =>
      api.listPortalTickets({
        ...(pageParam ? { after: pageParam } : {}),
        ...(search.trim() ? { search: search.trim() } : {}),
        kind,
        signal,
        tenantId,
      }),
    getNextPageParam: (lastPage) => lastPage.nextCursor,
  });
  const items = tickets.data?.pages.flatMap((page) => page.items) ?? [];

  return (
    <section
      className="portal-inventory"
      aria-labelledby="shared-incidents-title"
    >
      <PortalInventoryFilters
        canReadAlerts={canReadAlerts}
        canReadCases={canReadCases}
        kind={kind}
        onKindChange={onKindChange}
        search={search}
        setSearch={setSearch}
        tickets={tickets}
      />

      {tickets.isPending ? (
        <PortalLoading label="Loading shared incidents" />
      ) : null}
      {tickets.isError ? (
        <FocusedError
          title="Shared incidents unavailable"
          message={describePortalError(tickets.error)}
        />
      ) : null}
      {!tickets.isPending && items.length === 0 ? (
        <PortalEmpty
          title="No incidents are shared"
          detail="Only incidents explicitly linked to this exact contact appear here."
        />
      ) : null}
      {items.length > 0 ? (
        <div className="portal-ticket-grid">
          {items.map((ticket) => (
            <button
              className="portal-ticket-card"
              key={ticket.id}
              type="button"
              onClick={() => onSelect(ticket.id)}
            >
              <span className="portal-ticket-card__kind">
                {kind === "alert" ? (
                  <BellRing aria-hidden="true" />
                ) : (
                  <BriefcaseBusiness aria-hidden="true" />
                )}
                {ticketNumber(ticket)}
              </span>
              <strong>{ticket.title}</strong>
              <p>{ticketSummary(ticket)}</p>
              <span className="portal-ticket-card__meta">
                <Badge variant="outline">{ticket.workflow.stateKey}</Badge>
                <small>
                  {ticket.severity} · updated {formatDate(ticket.updatedAt)}
                </small>
              </span>
            </button>
          ))}
        </div>
      ) : null}
      {tickets.hasNextPage ? (
        <Button
          className="portal-load-more"
          variant="outline"
          disabled={tickets.isFetchingNextPage}
          onClick={() => void tickets.fetchNextPage()}
        >
          {tickets.isFetchingNextPage
            ? "Loading…"
            : "Load more shared incidents"}
        </Button>
      ) : null}
    </section>
  );
}

function PortalTicketDetail({
  api,
  canComment,
  canExport,
  canReadAttachments,
  csrfToken,
  kind,
  onBack,
  resourceId,
  tenantId,
}: {
  api: ContactPortalApi;
  canComment: boolean;
  canExport: boolean;
  canReadAttachments: boolean;
  csrfToken: string;
  kind: PortalKind;
  onBack: () => void;
  resourceId: string;
  tenantId: string;
}): React.JSX.Element {
  const ticket = useQuery({
    queryKey: ["customer-portal-ticket", tenantId, kind, resourceId],
    queryFn: ({ signal }) =>
      api.getPortalTicket({ kind, resourceId, signal, tenantId }),
  });
  const exportFile = useMutation({
    mutationFn: () => api.downloadPortalTicket({ kind, resourceId, tenantId }),
    onSuccess: saveCustomerPortalExport,
  });

  return (
    <section className="portal-detail" aria-labelledby="portal-detail-title">
      <Button variant="ghost" onClick={onBack}>
        <ChevronLeft aria-hidden="true" /> Back to shared incidents
      </Button>
      {ticket.isPending ? <PortalLoading label="Loading incident" /> : null}
      {ticket.isError ? (
        <FocusedError
          title="Incident unavailable"
          message={describePortalError(ticket.error)}
        />
      ) : null}
      {ticket.data ? (
        <>
          <header className="portal-detail__heading">
            <div>
              <p className="section-label">{ticketNumber(ticket.data.value)}</p>
              <h2 id="portal-detail-title">{ticket.data.value.title}</h2>
              <p>{ticketSummary(ticket.data.value)}</p>
            </div>
            <div className="portal-detail__status">
              <Badge>{ticket.data.value.workflow.stateKey}</Badge>
              <span>{ticket.data.value.severity} severity</span>
              <span>Updated {formatDate(ticket.data.value.updatedAt)}</span>
              {canExport ? (
                <Button
                  size="sm"
                  variant="outline"
                  disabled={exportFile.isPending}
                  onClick={() => exportFile.mutate()}
                >
                  {exportFile.isPending ? (
                    <LoaderCircle className="is-spinning" aria-hidden="true" />
                  ) : (
                    <Download aria-hidden="true" />
                  )}
                  {exportFile.isPending ? "Preparing CSV…" : "Download CSV"}
                </Button>
              ) : null}
              {exportFile.isError ? (
                <span className="portal-export-error" role="alert">
                  {describePortalError(exportFile.error)}
                </span>
              ) : null}
            </div>
          </header>
          <div className="portal-detail__layout">
            <Card className="portal-detail__overview">
              <CardHeader>
                <CardTitle>Customer overview</CardTitle>
                <CardDescription>
                  Public description supplied by the incident team.
                </CardDescription>
              </CardHeader>
              <CardContent>
                <SafeMarkdown markdown={ticketDescription(ticket.data.value)} />
              </CardContent>
            </Card>
            <TicketSlaPanel
              api={slaAdminApi}
              canOverride={false}
              canRead
              csrfToken={csrfToken}
              expectedAudience="customer"
              kind={kind}
              objectId={resourceId}
              tenantId={tenantId}
            />
            {canReadAttachments ? (
              <PortalAttachments
                key={`${tenantId}:${kind}:${resourceId}`}
                api={api}
                csrfToken={csrfToken}
                kind={kind}
                resourceId={resourceId}
                tenantId={tenantId}
              />
            ) : null}
            <PortalActivityFeed
              api={api}
              kind={kind}
              resourceId={resourceId}
              tenantId={tenantId}
            />
            <PortalCommentPanel
              api={api}
              canComment={canComment}
              csrfToken={csrfToken}
              kind={kind}
              resourceId={resourceId}
              tenantId={tenantId}
            />
          </div>
        </>
      ) : null}
    </section>
  );
}

function PortalAttachments({
  api,
  csrfToken,
  kind,
  resourceId,
  tenantId,
}: {
  api: ContactPortalApi;
  csrfToken: string;
  kind: PortalKind;
  resourceId: string;
  tenantId: string;
}): React.JSX.Element {
  const prepareController = useRef<AbortController | null>(null);
  const [prepared, setPrepared] =
    useState<CustomerPortalPreparedAttachmentDownload>();
  const attachments = useInfiniteQuery({
    queryKey: ["customer-portal-attachments", tenantId, kind, resourceId],
    gcTime: 0,
    initialPageParam: undefined as string | undefined,
    queryFn: ({ pageParam, signal }) =>
      api.listPortalAttachments({
        ...(pageParam ? { after: pageParam } : {}),
        kind,
        resourceId,
        signal,
        tenantId,
      }),
    getNextPageParam: (lastPage, pages) =>
      unseenNextCursor(lastPage.nextCursor, pages),
  });
  // react-doctor-disable-next-line react-doctor/query-mutation-missing-invalidation -- Preparing a short-lived download capability does not mutate the attachment inventory; invalidation would discard the capability immediately.
  const prepare = useMutation({
    mutationFn: (attachment: CustomerPortalAttachment) => {
      prepareController.current?.abort();
      const controller = new AbortController();
      prepareController.current = controller;
      return api.preparePortalAttachmentDownload({
        attachmentId: attachment.id,
        csrfToken,
        kind,
        resourceId,
        signal: controller.signal,
        tenantId,
      });
    },
    onSuccess: setPrepared,
  });
  const isRevalidating =
    attachments.isFetching && !attachments.isFetchingNextPage;
  const items =
    attachments.isError || isRevalidating
      ? []
      : (attachments.data?.pages.flatMap((page) => page.items) ?? []);

  useEffect(
    () => () => {
      prepareController.current?.abort();
    },
    [],
  );
  useEffect(() => {
    if (!prepared) return undefined;
    const remaining = Date.parse(prepared.expiresAt) - Date.now();
    if (remaining <= 0) {
      setPrepared(undefined);
      return undefined;
    }
    const timer = window.setTimeout(
      () => setPrepared(undefined),
      Math.min(remaining, 2_147_483_647),
    );
    return () => window.clearTimeout(timer);
  }, [prepared]);

  return (
    <Card
      className="portal-attachments"
      aria-labelledby="portal-shared-attachments-title"
    >
      <CardHeader>
        <CardTitle
          id="portal-shared-attachments-title"
          role="heading"
          aria-level={3}
        >
          Shared attachments
        </CardTitle>
        <CardDescription>
          Only public files that passed security checks are listed. Each
          download is reauthorized and expires quickly.
        </CardDescription>
      </CardHeader>
      <CardContent aria-live="polite" aria-busy={attachments.isFetching}>
        {isRevalidating ? (
          <PortalLoading label="Loading shared attachments" />
        ) : null}
        {attachments.isError ? (
          <FocusedError
            title="Attachments unavailable"
            message={describePortalError(attachments.error)}
          />
        ) : null}
        {!isRevalidating && !attachments.isError && items.length === 0 ? (
          <PortalEmpty
            title="No shared attachments"
            detail="Files explicitly shared by the incident team will appear here after security checks finish."
          />
        ) : null}
        {items.length > 0 ? (
          <ul
            className="portal-attachment-list"
            aria-label="Customer-visible attachments"
          >
            {items.map((attachment) => {
              const isPreparing =
                prepare.isPending && prepare.variables?.id === attachment.id;
              const download =
                prepared?.attachment.id === attachment.id
                  ? prepared
                  : undefined;
              return (
                <li key={attachment.id}>
                  <div className="portal-attachment-list__identity">
                    <Paperclip aria-hidden="true" />
                    <span>
                      <strong>{attachment.originalFilename}</strong>
                      <time dateTime={attachment.uploadedAt}>
                        Shared {formatDate(attachment.uploadedAt)}
                      </time>
                    </span>
                  </div>
                  <div className="portal-attachment-list__actions">
                    <Button
                      type="button"
                      size="sm"
                      variant="outline"
                      aria-label={`Prepare download for ${attachment.originalFilename}`}
                      disabled={prepare.isPending}
                      onClick={() => {
                        setPrepared(undefined);
                        prepare.reset();
                        prepare.mutate(attachment);
                      }}
                    >
                      {isPreparing ? (
                        <LoaderCircle
                          className="is-spinning"
                          aria-hidden="true"
                        />
                      ) : (
                        <Download aria-hidden="true" />
                      )}
                      {isPreparing
                        ? "Preparing…"
                        : download
                          ? "Refresh download"
                          : "Prepare download"}
                    </Button>
                    {download ? (
                      <a
                        className="portal-attachment-download"
                        href={download.downloadUrl}
                        download={attachment.originalFilename}
                        referrerPolicy="no-referrer"
                        rel="noreferrer noopener"
                        target="_blank"
                        aria-label={`Download ${attachment.originalFilename}`}
                      >
                        <Download aria-hidden="true" /> Download file
                      </a>
                    ) : null}
                  </div>
                </li>
              );
            })}
          </ul>
        ) : null}
        {prepare.isError ? (
          <FocusedError
            title="Download could not be prepared"
            message={describePortalError(prepare.error)}
          />
        ) : null}
        {!attachments.isError && attachments.hasNextPage ? (
          <Button
            size="sm"
            variant="outline"
            disabled={attachments.isFetchingNextPage}
            onClick={() => void attachments.fetchNextPage()}
          >
            {attachments.isFetchingNextPage
              ? "Loading more…"
              : "Load more attachments"}
          </Button>
        ) : null}
      </CardContent>
    </Card>
  );
}

function PortalActivityFeed({
  api,
  kind,
  resourceId,
  tenantId,
}: {
  api: ContactPortalApi;
  kind: PortalKind;
  resourceId: string;
  tenantId: string;
}): React.JSX.Element {
  const activities = useInfiniteQuery({
    queryKey: ["customer-portal-activity", tenantId, kind, resourceId],
    initialPageParam: undefined as string | undefined,
    queryFn: ({ pageParam, signal }) =>
      api.listPortalActivities({
        ...(pageParam ? { after: pageParam } : {}),
        kind,
        resourceId,
        signal,
        tenantId,
      }),
    getNextPageParam: (lastPage) => lastPage.nextCursor,
  });
  const items = activities.data?.pages.flatMap((page) => page.items) ?? [];

  return (
    <Card className="portal-stream">
      <CardHeader>
        <CardTitle>Public activity</CardTitle>
        <CardDescription>
          Private lifecycle events are removed before pagination.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {activities.isPending ? (
          <PortalLoading label="Loading public activity" />
        ) : null}
        {activities.isError ? (
          <FocusedError
            title="Activity unavailable"
            message={describePortalError(activities.error)}
          />
        ) : null}
        {!activities.isPending && items.length === 0 ? (
          <PortalEmpty
            title="No public activity"
            detail="Customer-visible updates will appear here."
          />
        ) : null}
        <ol className="portal-timeline">
          {items.map((item) => (
            <ActivityItem item={item} key={item.id} />
          ))}
        </ol>
        {activities.hasNextPage ? (
          <Button
            size="sm"
            variant="outline"
            onClick={() => void activities.fetchNextPage()}
          >
            Load earlier activity
          </Button>
        ) : null}
      </CardContent>
    </Card>
  );
}

function ActivityItem({ item }: { item: CustomerActivity }): React.JSX.Element {
  return (
    <li>
      <span aria-hidden="true" />
      <div>
        <strong>{item.summary}</strong>
        <small>
          {item.actor.displayName} · {formatDate(item.occurredAt)}
        </small>
      </div>
    </li>
  );
}

function PortalPreferences({
  api,
  contact,
  csrfToken,
  error,
  loading,
  tenantId,
}: {
  api: ContactPortalApi;
  contact: Versioned<CustomerPortalContact> | undefined;
  csrfToken: string;
  error: Error | null;
  loading: boolean;
  tenantId: string;
}): React.JSX.Element {
  if (loading) return <PortalLoading label="Loading contact preferences" />;
  if (error)
    return (
      <FocusedError
        title="Preferences unavailable"
        message={describePortalError(error)}
      />
    );
  if (!contact)
    return (
      <PortalEmpty
        title="Contact identity unavailable"
        detail="No exact active contact is linked to this session."
      />
    );
  return (
    <PortalPreferenceForm
      api={api}
      contact={contact}
      csrfToken={csrfToken}
      key={`${contact.value.id}:${contact.value.version}`}
      tenantId={tenantId}
    />
  );
}

function PortalPreferenceForm({
  api,
  contact,
  csrfToken,
  tenantId,
}: {
  api: ContactPortalApi;
  contact: Versioned<CustomerPortalContact>;
  csrfToken: string;
  tenantId: string;
}): React.JSX.Element {
  const client = useQueryClient();
  const preferenceAttempt = useRef<IdempotencyReference>({ current: null });
  const [categories, setCategories] = useState(() =>
    contact.value.notificationCategories.join(", "),
  );
  const [emailAllowed, setEmailAllowed] = useState(
    () => contact.value.emailAllowed,
  );
  const [windowText, setWindowText] = useState(() =>
    formatNotificationWindows(contact.value.notificationWindows),
  );
  const mutation = useMutation({
    mutationFn: () => {
      const body = {
        emailAllowed,
        notificationCategories: stableKeys(categories),
        notificationWindows: parseNotificationWindows(windowText),
      };
      return api.replacePortalPreferences({
        body,
        csrfToken,
        etag: contact.etag,
        idempotencyKey: idempotencyKeyForPayload(preferenceAttempt.current, {
          body,
          etag: contact.etag,
          operation: "portal.preference.replace",
          tenantId,
        }),
        tenantId,
      });
    },
    onSuccess: async () => {
      preferenceAttempt.current.current = null;
      await client.invalidateQueries({
        queryKey: ["customer-portal-contact", tenantId],
      });
    },
  });

  return (
    <section className="portal-preferences" aria-labelledby="preferences-title">
      <div className="portal-preferences__identity">
        <p className="section-label">Exact linked contact</p>
        <h2 id="preferences-title">Notification preferences</h2>
        <dl>
          <div>
            <dt>Name</dt>
            <dd>
              {contact.value.firstName} {contact.value.lastName}
            </dd>
          </div>
          <div>
            <dt>Destination</dt>
            <dd>{contact.value.email}</dd>
          </div>
          <div>
            <dt>Function</dt>
            <dd>{contact.value.function}</dd>
          </div>
          <div>
            <dt>Timezone</dt>
            <dd>{contact.value.timezone}</dd>
          </div>
        </dl>
      </div>
      <form
        className="portal-preferences__form"
        onSubmit={(event) => {
          event.preventDefault();
          mutation.mutate();
        }}
      >
        <div>
          <p className="section-label">Local delivery window</p>
          <h3>When should notifications arrive?</h3>
          <p>
            Use ISO weekdays (Monday 1 through Sunday 7) and half-open local
            times. Daylight-saving changes are evaluated in{" "}
            {contact.value.timezone} by the server.
          </p>
        </div>
        <Label>
          Notification categories
          <Input
            value={categories}
            onChange={(event) => setCategories(event.currentTarget.value)}
            placeholder="incident, sla"
          />
        </Label>
        <Label>
          Windows, one per line
          <Textarea
            value={windowText}
            onChange={(event) => setWindowText(event.currentTarget.value)}
            placeholder={"1 09:00-17:00\n2 09:00-17:00"}
          />
        </Label>
        <Label className="portal-preferences__check">
          <input
            type="checkbox"
            checked={emailAllowed}
            onChange={(event) => setEmailAllowed(event.currentTarget.checked)}
          />
          Allow email notifications
        </Label>
        {mutation.isError ? (
          <FocusedError
            title="Preferences were not saved"
            message={describePortalError(mutation.error)}
          />
        ) : null}
        <Button type="submit" disabled={mutation.isPending}>
          {mutation.isPending ? "Saving…" : "Save preferences"}
        </Button>
      </form>
    </section>
  );
}

function ticketNumber(ticket: PortalTicket): string {
  return "alertNumber" in ticket ? ticket.alertNumber : ticket.caseNumber;
}

function ticketSummary(ticket: PortalTicket): string {
  return "summary" in ticket && ticket.summary
    ? ticket.summary
    : ticket.description;
}

function ticketDescription(ticket: PortalTicket): string {
  return (
    ticket.description ||
    ticketSummary(ticket) ||
    "No customer description has been published."
  );
}

function stableKeys(value: string): string[] {
  return [
    ...new Set(
      value
        .split(",")
        .map((item) => item.trim())
        .filter(Boolean),
    ),
  ].toSorted();
}

function unseenNextCursor(
  cursor: string | undefined,
  pages: ReadonlyArray<{ nextCursor?: string }>,
): string | undefined {
  return cursor &&
    !pages.slice(0, -1).some((page) => page.nextCursor === cursor)
    ? cursor
    : undefined;
}

function formatDate(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? "unknown time"
    : portalDateFormatter.format(date);
}

function PortalLoading({ label }: { label: string }): React.JSX.Element {
  return (
    <div className="portal-loading" role="status">
      <LoaderCircle className="is-spinning" aria-hidden="true" /> {label}…
    </div>
  );
}

function PortalEmpty({
  detail,
  title,
}: {
  detail: string;
  title: string;
}): React.JSX.Element {
  return (
    <div className="portal-empty">
      <MessageSquareText aria-hidden="true" />
      <strong>{title}</strong>
      <p>{detail}</p>
    </div>
  );
}

function PortalBoundary({
  loading = false,
}: {
  loading?: boolean;
}): React.JSX.Element {
  return (
    <div
      className="content content--narrow portal-boundary"
      role={loading ? "status" : undefined}
    >
      {loading ? (
        <LoaderCircle className="is-spinning" aria-hidden="true" />
      ) : (
        <ShieldX aria-hidden="true" />
      )}
      <p className="section-label">Customer portal boundary</p>
      <h1>
        {loading
          ? "Checking customer authority…"
          : "Customer portal unavailable."}
      </h1>
      <p>
        {loading
          ? "No customer projection is requested until live tenant authority is ready."
          : "An exact active contact link and a live portal permission are required. Navigation alone never grants access."}
      </p>
    </div>
  );
}

function describePortalError(error: unknown): string {
  if (error instanceof ContactApiError) return error.message;
  return "The customer portal operation could not be completed.";
}

const uuidV7Pattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

const portalDateFormatter = new Intl.DateTimeFormat(undefined, {
  day: "2-digit",
  hour: "2-digit",
  minute: "2-digit",
  month: "short",
  timeZoneName: "short",
  year: "numeric",
});

function preferredPortalKind(
  requested: string | null,
  canReadAlerts: boolean,
  canReadCases: boolean,
): PortalKind {
  if (requested === "case" && canReadCases) return "case";
  if (requested === "alert" && canReadAlerts) return "alert";
  return canReadAlerts ? "alert" : "case";
}

interface PortalInventoryFiltersProps {
  canReadAlerts: boolean;
  canReadCases: boolean;
  kind: PortalKind;
  onKindChange: (kind: PortalKind) => void;
  search: string;
  setSearch: React.Dispatch<React.SetStateAction<string>>;
  tickets: { isFetching: boolean; refetch: () => Promise<unknown> };
}

function PortalInventoryFilters({
  canReadAlerts,
  canReadCases,
  kind,
  onKindChange,
  search,
  setSearch,
  tickets,
}: PortalInventoryFiltersProps): React.JSX.Element {
  return (
    <div className="portal-inventory__toolbar">
      <div>
        <p className="section-label">Exact contact links</p>
        <h2 id="shared-incidents-title">Shared incidents</h2>
      </div>
      <div className="portal-inventory__controls">
        <div
          className="portal-kind-switch"
          role="group"
          aria-label="Incident kind"
        >
          {canReadAlerts ? (
            <Button
              size="sm"
              variant={kind === "alert" ? "default" : "outline"}
              onClick={() => onKindChange("alert")}
            >
              <BellRing aria-hidden="true" /> Alerts
            </Button>
          ) : null}
          {canReadCases ? (
            <Button
              size="sm"
              variant={kind === "case" ? "default" : "outline"}
              onClick={() => onKindChange("case")}
            >
              <BriefcaseBusiness aria-hidden="true" /> Cases
            </Button>
          ) : null}
        </div>
        <Label className="portal-search">
          <Search aria-hidden="true" />
          <span className="sr-only">Search shared incidents</span>
          <Input
            value={search}
            onChange={(event) => setSearch(event.currentTarget.value)}
            placeholder="Search shared incidents…"
          />
        </Label>
        <Button
          size="sm"
          variant="outline"
          disabled={tickets.isFetching}
          onClick={() => void tickets.refetch()}
        >
          <RefreshCw
            className={tickets.isFetching ? "is-spinning" : undefined}
            aria-hidden="true"
          />
          Refresh
        </Button>
      </div>
    </div>
  );
}

interface PortalViewSwitchProps {
  canManagePreferences: boolean;
  canReadAlerts: boolean;
  canReadCases: boolean;
  setView: React.Dispatch<React.SetStateAction<"incidents" | "preferences">>;
  view: "incidents" | "preferences";
}

function PortalViewSwitch({
  canManagePreferences,
  canReadAlerts,
  canReadCases,
  setView,
  view,
}: PortalViewSwitchProps): React.JSX.Element {
  return (
    <div
      className="customer-portal__view-switch"
      role="group"
      aria-label="Portal view"
    >
      {canReadAlerts || canReadCases ? (
        <Button
          variant={view === "incidents" ? "default" : "outline"}
          onClick={() => setView("incidents")}
        >
          <Activity aria-hidden="true" /> Shared incidents
        </Button>
      ) : null}
      {canManagePreferences ? (
        <Button
          variant={view === "preferences" ? "default" : "outline"}
          onClick={() => setView("preferences")}
        >
          <CalendarClock aria-hidden="true" /> Contact preferences
        </Button>
      ) : null}
    </div>
  );
}
