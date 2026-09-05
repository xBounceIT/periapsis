import {
  useInfiniteQuery,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import type {
  TicketBulkQuerySourceRequest,
  TicketBulkTargetPin,
  TicketExportJobRequest,
} from "@periapsis/contracts";
import { Button } from "@periapsis/ui/components/ui/button";
import { Input } from "@periapsis/ui/components/ui/input";
import {
  ArrowDown,
  BellRing,
  BriefcaseBusiness,
  Filter,
  Plus,
  RefreshCw,
  Search,
} from "lucide-react";
import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type FormEvent,
} from "react";
import { Link, useSearchParams } from "react-router";

import { useSession } from "../auth/session-context";
import { useTenantAuthority } from "../auth/tenant-authority-context";
import { FocusedError } from "../components/focused-error";
import { ServerDenied } from "../components/server-denied";
import {
  TicketingApiError,
  describeTicketingError,
  type TicketKind,
  type TicketListFilters,
} from "../lib/ticketing-api";
import {
  TicketColumnCatalogApiError,
  type TicketDynamicColumnCatalogItem,
} from "../lib/ticket-column-catalog-api";
import type {
  TenantAuthorizationScopeView,
  TenantPermissionKeyView,
} from "../lib/phase-two-types";
import { useTicketingApi } from "./ticketing-context";
import {
  alertSeverities,
  hasAnyTicketPermission,
  humanizeKey,
  kindLabel,
  kindLabelPlural,
  parseStatusFilter,
  ticketPriorities,
  ticketSorts,
} from "./ticketing-model";
import { TicketDataTable } from "./ticket-data-table";
import {
  TicketBulkControls,
  type TicketBulkAction,
} from "./ticket-bulk-controls";
import { TicketExportControls } from "./ticket-export-controls";
import { useTicketColumnCatalogApi } from "./ticket-column-catalog-context";
import { SavedViewControls } from "./saved-view-controls";
import {
  defaultTicketTableColumns,
  inlineSavedViewSpec,
  parseSavedViewURL,
  sameTableColumns,
  savedViewSpecInput,
  savedViewURL,
  tableColumnsFromSavedView,
  type TicketTableColumnSpec,
} from "./saved-view-model";

interface TicketListPageProps {
  kind: TicketKind;
}

interface FilterDraft {
  customerVisible: "all" | "customer" | "internal";
  priority: "all" | (typeof ticketPriorities)[number];
  queue: "all" | "assigned_to_me" | "my_operator_teams" | "unassigned";
  search: string;
  severity: "all" | (typeof alertSeverities)[number];
  sort: (typeof ticketSorts)[number];
  status: string;
}

const initialFilters: FilterDraft = {
  customerVisible: "all",
  priority: "all",
  queue: "all",
  search: "",
  severity: "all",
  sort: "updated_at_desc",
  status: "",
};

const ticketQueues = [
  "assigned_to_me",
  "my_operator_teams",
  "unassigned",
] as const;
const customerVisibilityFilters = ["customer", "internal"] as const;
const workflowStatePattern = /^[a-z][a-z0-9_-]{0,63}$/u;
const maximumWorkflowStateFilters = 20;
const maximumSearchLength = 200;

export function AlertListPage(): React.JSX.Element {
  return <TicketListPage kind="alert" />;
}

export function CaseListPage(): React.JSX.Element {
  return <TicketListPage kind="case" />;
}

export function TicketListPage({
  kind,
}: TicketListPageProps): React.JSX.Element {
  const api = useTicketingApi();
  const columnCatalogApi = useTicketColumnCatalogApi();
  const { clearSession, session } = useSession();
  const authority = useTenantAuthority();
  const queryClient = useQueryClient();
  const tenantId = session.activeTenantId;
  const [searchParameters, setSearchParameters] = useSearchParams();
  const serializedSearch = searchParameters.toString();
  const viewSelection = useMemo(
    () => parseSavedViewURL(searchParameters),
    // URLSearchParams is mutable; the serialized value is the stable input.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [serializedSearch],
  );
  const committedDraft = useMemo(
    () => ticketFilterDraftFromURL(searchParameters),
    // URLSearchParams is mutable; the serialized value is the stable input.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [serializedSearch],
  );
  const [draft, setDraft] = useState<FilterDraft>(committedDraft);
  const filters = useMemo(
    () => ticketFiltersFromDraft(committedDraft),
    [committedDraft],
  );
  const [tableColumns, setTableColumns] = useState<TicketTableColumnSpec[]>(
    () => defaultTicketTableColumns.map((column) => ({ ...column })),
  );
  const [bulkTargets, setBulkTargets] = useState<TicketBulkTargetPin[]>([]);
  const [bulkSelectionReset, setBulkSelectionReset] = useState(0);
  const [columnCatalogRequested, setColumnCatalogRequested] = useState(false);
  const createPermission = kind === "alert" ? "alert.create" : "case.create";
  const readPermission = kind === "alert" ? "alert.read" : "case.read";
  const canCreate = hasAnyTicketPermission(
    authority.hasPermission,
    createPermission,
  );
  const canRead = hasAnyTicketPermission(
    authority.hasPermission,
    readPermission,
  );
  const liveReadAuthority = authority.status === "ready" && canRead;
  const availableBulkActions = useMemo(
    () => bulkActionsForAuthority(kind, authority.hasPermission),
    [authority.hasPermission, kind],
  );
  const allowPublicExportComments = hasAnyTicketPermission(
    authority.hasPermission,
    kind === "alert" ? "alert.comment.public" : "case.comment.public",
  );
  const allowPrivateExportComments = hasAnyTicketPermission(
    authority.hasPermission,
    kind === "alert" ? "alert.comment.private" : "case.comment.private",
  );
  const canReadSlaCatalog = hasAnyTicketPermission(
    authority.hasPermission,
    "sla.read",
  );
  const canReadCustomFieldCatalog = hasAnyTicketPermission(
    authority.hasPermission,
    "custom_field.read",
  );

  useEffect(() => setDraft(committedDraft), [committedDraft]);
  useEffect(() => setColumnCatalogRequested(false), [kind, tenantId]);

  const viewsQuery = useInfiniteQuery({
    enabled: Boolean(tenantId) && liveReadAuthority,
    initialPageParam: undefined as string | undefined,
    queryKey: ["saved-ticket-views", tenantId, kind],
    queryFn: ({ pageParam, signal }) =>
      api.listSavedTicketViews({
        ...(pageParam ? { after: pageParam } : {}),
        includeArchived: true,
        kind,
        tenantId: tenantId!,
        signal,
      }),
    getNextPageParam: (page, pages) =>
      page.nextCursor &&
      !pages
        .slice(0, -1)
        .some((candidate) => candidate.nextCursor === page.nextCursor)
        ? page.nextCursor
        : undefined,
  });
  const selectedViewId =
    viewSelection.kind === "selected" ? viewSelection.viewId : undefined;
  const selectedViewQuery = useQuery({
    enabled:
      Boolean(tenantId) && liveReadAuthority && selectedViewId !== undefined,
    queryKey: ["saved-ticket-view", tenantId, kind, selectedViewId],
    queryFn: ({ signal }) =>
      api.getSavedTicketView({
        kind,
        tenantId: tenantId!,
        viewId: selectedViewId!,
        signal,
      }),
  });
  const customFieldCatalogQuery = useInfiniteQuery({
    enabled:
      Boolean(tenantId) &&
      liveReadAuthority &&
      columnCatalogRequested &&
      canReadCustomFieldCatalog,
    initialPageParam: undefined as string | undefined,
    queryKey: ["ticket-column-catalog", tenantId, kind, "custom_field"],
    queryFn: ({ pageParam, signal }) =>
      columnCatalogApi.listCustomFields({
        ...(pageParam ? { after: pageParam } : {}),
        kind,
        tenantId: tenantId!,
        signal,
      }),
    getNextPageParam: (page, pages) =>
      page.nextCursor &&
      !pages
        .slice(0, -1)
        .some((candidate) => candidate.nextCursor === page.nextCursor)
        ? page.nextCursor
        : undefined,
  });
  const slaCatalogQuery = useInfiniteQuery({
    enabled:
      Boolean(tenantId) &&
      liveReadAuthority &&
      columnCatalogRequested &&
      canReadSlaCatalog,
    initialPageParam: undefined as string | undefined,
    queryKey: ["ticket-column-catalog", tenantId, kind, "sla"],
    queryFn: ({ pageParam, signal }) =>
      columnCatalogApi.listSlaColumns({
        ...(pageParam ? { after: pageParam } : {}),
        tenantId: tenantId!,
        signal,
      }),
    getNextPageParam: (page, pages) =>
      page.nextCursor &&
      !pages
        .slice(0, -1)
        .some((candidate) => candidate.nextCursor === page.nextCursor)
        ? page.nextCursor
        : undefined,
  });
  const selectedView = selectedViewQuery.data;
  const selectedViewScope = selectedView
    ? `${selectedView.value.id}:${selectedView.value.revision}:${selectedView.value.specSha256}`
    : viewSelection.kind;

  useEffect(() => {
    const next = selectedView
      ? tableColumnsFromSavedView(selectedView.value.spec.columns)
      : defaultTicketTableColumns.map((column) => ({ ...column }));
    setTableColumns((current) =>
      sameTableColumns(current, next) ? current : next,
    );
  }, [selectedViewScope]);

  const handleColumnsChange = useCallback((next: TicketTableColumnSpec[]) => {
    setTableColumns((current) =>
      sameTableColumns(current, next) ? current : next,
    );
  }, []);
  const currentSpec = useMemo(
    () =>
      selectedView
        ? savedViewSpecInput(selectedView.value.spec, tableColumns)
        : inlineSavedViewSpec(filters, tableColumns),
    [filters, selectedView, tableColumns],
  );
  const bulkQuery = useMemo<TicketBulkQuerySourceRequest>(
    () =>
      selectedView
        ? {
            source: "saved_view",
            savedView: {
              expectedRevision: selectedView.value.revision,
              expectedSpecSha256: selectedView.value.specSha256,
              id: selectedView.value.id,
            },
          }
        : { source: "inline", spec: currentSpec },
    [currentSpec, selectedView],
  );
  const exportSource = useMemo<TicketExportJobRequest["source"]>(
    () =>
      selectedView
        ? {
            source: "saved_view",
            savedView: {
              expectedRevision: selectedView.value.revision,
              expectedSpecSha256: selectedView.value.specSha256,
              id: selectedView.value.id,
            },
          }
        : { source: "inline", spec: currentSpec },
    [currentSpec, selectedView],
  );
  const selectedCanExecute = selectedView?.value.status === "active";
  const queueExecutable =
    viewSelection.kind === "none" ||
    (viewSelection.kind === "selected" && selectedCanExecute);
  const selectedResolutionPending =
    viewSelection.kind === "selected" && selectedViewQuery.isPending;
  const effectiveFilters = useMemo<TicketListFilters>(
    () =>
      selectedViewId === undefined
        ? filters
        : { limit: 30, viewId: selectedViewId },
    [filters, selectedViewId],
  );
  const ticketsQuery = useInfiniteQuery({
    enabled:
      Boolean(tenantId) &&
      liveReadAuthority &&
      viewSelection.kind !== "invalid" &&
      queueExecutable,
    initialPageParam: undefined as string | undefined,
    queryKey: ["tickets", kind, tenantId, effectiveFilters, selectedViewScope],
    queryFn: async ({ pageParam, signal }) => {
      const page = await api.listTickets(
        kind,
        tenantId!,
        { ...effectiveFilters, ...(pageParam ? { after: pageParam } : {}) },
        signal,
      );
      if (
        selectedView &&
        (page.appliedView?.id !== selectedView.value.id ||
          page.appliedView.revision !== selectedView.value.revision ||
          page.appliedView.specSha256 !== selectedView.value.specSha256)
      ) {
        throw new TicketingApiError(
          "The queue was not produced from the current saved-view revision.",
          undefined,
          "projection_mismatch",
        );
      }
      return page;
    },
    getNextPageParam: (page, pages) =>
      page.nextCursor &&
      !pages
        .slice(0, -1)
        .some((candidate) => candidate.nextCursor === page.nextCursor)
        ? page.nextCursor
        : undefined,
  });
  const handledAccessError = useRef<unknown>(undefined);
  const accessError =
    selectedViewQuery.error ??
    viewsQuery.error ??
    ticketsQuery.error ??
    customFieldCatalogQuery.error ??
    slaCatalogQuery.error;
  useEffect(() => {
    if (handledAccessError.current === accessError) {
      return;
    }
    if (
      !(accessError instanceof TicketingApiError) &&
      !(accessError instanceof TicketColumnCatalogApiError)
    ) {
      return;
    }
    handledAccessError.current = accessError;
    if (accessError.status === 401) clearSession(session.id);
    if (accessError.status === 403) authority.reload();
  }, [accessError, authority.reload, clearSession, session.id]);

  useEffect(() => {
    setBulkTargets([]);
    setBulkSelectionReset((current) => current + 1);
  }, [kind, selectedViewScope, serializedSearch, tenantId]);

  const handleBulkSelectionChange = useCallback(
    (next: TicketBulkTargetPin[]) => {
      setBulkTargets((current) =>
        sameBulkTargets(current, next) ? current : next,
      );
    },
    [],
  );

  if (!tenantId) {
    return <NoTenant kind={kind} />;
  }

  if (authority.status === "loading") {
    return <TicketAuthorityLoading kind={kind} />;
  }

  if (!liveReadAuthority) {
    return <ServerDenied resource={`${kindLabelPlural(kind)} inventory`} />;
  }

  if (
    ticketsQuery.error instanceof TicketingApiError &&
    ticketsQuery.error.status === 403
  ) {
    return <ServerDenied resource={`${kindLabelPlural(kind)} inventory`} />;
  }

  const items = ticketsQuery.data?.pages.flatMap((page) => page.items) ?? [];
  const views = viewsQuery.data?.pages.flatMap((page) => page.items) ?? [];
  const queueVisible =
    viewSelection.kind !== "invalid" &&
    queueExecutable &&
    !selectedViewQuery.isError;
  const visibleItems = queueVisible ? items : [];
  const dynamicColumnCatalog = uniqueDynamicColumnCatalog([
    ...(customFieldCatalogQuery.data?.pages.flatMap((page) => page.items) ??
      []),
    ...(slaCatalogQuery.data?.pages.flatMap((page) => page.items) ?? []),
  ]);
  const queuePending =
    selectedResolutionPending || (queueVisible && ticketsQuery.isPending);

  function applyFilters(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault();
    setSearchParameters(ticketFilterURLFromDraft(draft));
  }

  function resetFilters(): void {
    setDraft(initialFilters);
    setSearchParameters({});
  }

  function selectView(viewId?: string): void {
    setSearchParameters(savedViewURL(viewId));
  }

  function reloadViews(): void {
    void queryClient.invalidateQueries({
      queryKey: ["saved-ticket-views", tenantId, kind],
    });
    if (selectedViewId) {
      void queryClient.invalidateQueries({
        queryKey: ["saved-ticket-view", tenantId, kind, selectedViewId],
      });
    }
  }

  return (
    <div className="content ticket-list-page">
      <section
        className="page-heading ticket-heading"
        aria-labelledby="tickets-title"
      >
        <div>
          <p className="section-label">Incident desk / Phase 3</p>
          <h1 id="tickets-title">{kindLabelPlural(kind)}</h1>
          <p>
            {kind === "alert"
              ? "Triage incoming signals without turning the queue into a false authorization boundary."
              : "Coordinate investigations as separate, versioned Case aggregates."}
          </p>
        </div>
        {canCreate ? (
          <Button asChild>
            <Link to={`/${kind === "alert" ? "alerts" : "cases"}/new`}>
              <Plus aria-hidden="true" /> Create {kindLabel(kind).toLowerCase()}
            </Link>
          </Button>
        ) : null}
      </section>

      <SavedViewControls
        api={api}
        canPersist={liveReadAuthority}
        csrfToken={session.csrfToken}
        currentSpec={currentSpec}
        inventoryError={viewsQuery.error ?? undefined}
        inventoryHasMore={viewsQuery.hasNextPage}
        inventoryLoading={viewsQuery.isPending}
        inventoryLoadingMore={viewsQuery.isFetchingNextPage}
        kind={kind}
        onForbidden={authority.reload}
        onLoadMore={() => void viewsQuery.fetchNextPage()}
        onMutation={(result) => {
          queryClient.setQueryData(
            ["saved-ticket-view", tenantId, kind, result.value.id],
            { etag: result.etag, value: result.value },
          );
          void queryClient.invalidateQueries({
            queryKey: ["saved-ticket-views", tenantId, kind],
          });
          selectView(result.value.id);
        }}
        onReload={reloadViews}
        onSelect={selectView}
        onUnauthorized={() => clearSession(session.id)}
        selected={selectedView}
        selectedError={selectedViewQuery.error ?? undefined}
        selectedLoading={
          viewSelection.kind === "selected" && selectedViewQuery.isPending
        }
        selection={viewSelection}
        tenantId={tenantId}
        views={views}
      />

      <form
        className="ticket-filter-panel"
        onSubmit={applyFilters}
        role="search"
      >
        <div className="ticket-filter-panel__title">
          <span>
            <Filter aria-hidden="true" /> Queue filters
          </span>
          <small>Server-authorized projection</small>
        </div>
        <label className="ticket-search-field">
          <span>Search</span>
          <span>
            <Search aria-hidden="true" />
            <Input
              value={draft.search}
              maxLength={maximumSearchLength}
              onChange={(event) =>
                setDraft((current) => ({
                  ...current,
                  search: event.target.value,
                }))
              }
              placeholder={`Search ${kindLabelPlural(kind).toLowerCase()}`}
            />
          </span>
        </label>
        <FilterSelect
          label="Severity"
          value={draft.severity}
          onChange={(severity) =>
            setDraft((current) => ({ ...current, severity }))
          }
          options={["all", ...alertSeverities]}
        />
        <FilterSelect
          label="Priority"
          value={draft.priority}
          onChange={(priority) =>
            setDraft((current) => ({ ...current, priority }))
          }
          options={["all", ...ticketPriorities]}
        />
        <FilterSelect
          label="Queue"
          value={draft.queue}
          onChange={(queue) => setDraft((current) => ({ ...current, queue }))}
          options={["all", "unassigned", "assigned_to_me", "my_operator_teams"]}
        />
        <FilterSelect
          label="Visibility"
          value={draft.customerVisible}
          onChange={(customerVisible) =>
            setDraft((current) => ({ ...current, customerVisible }))
          }
          options={["all", "customer", "internal"]}
        />
        <label className="ticket-filter-field">
          <span>Workflow states</span>
          <Input
            value={draft.status}
            maxLength={240}
            onChange={(event) =>
              setDraft((current) => ({
                ...current,
                status: event.target.value,
              }))
            }
            placeholder="new, investigating"
          />
        </label>
        <FilterSelect
          label="Order"
          value={draft.sort}
          onChange={(sort) => setDraft((current) => ({ ...current, sort }))}
          options={[...ticketSorts]}
        />
        <div className="ticket-filter-panel__actions">
          <Button type="submit" size="sm">
            Apply filters
          </Button>
          <Button
            type="button"
            size="sm"
            variant="ghost"
            onClick={resetFilters}
          >
            Reset
          </Button>
        </div>
        {viewSelection.kind === "selected" ? (
          <p className="ticket-filter-panel__saved-view-hint">
            Applying these queue filters switches back to an unsaved current
            view.
          </p>
        ) : null}
      </form>

      {queueVisible && !selectedResolutionPending ? (
        <TicketExportControls
          allowPrivateComments={allowPrivateExportComments}
          allowPublicComments={allowPublicExportComments}
          csrfToken={session.csrfToken}
          kind={kind}
          onForbidden={authority.reload}
          onUnauthorized={() => clearSession(session.id)}
          source={exportSource}
          tenantId={tenantId}
        />
      ) : null}

      <section
        className="ticket-inventory"
        aria-busy={
          queuePending || (queueVisible && ticketsQuery.isFetchingNextPage)
        }
        aria-live="polite"
      >
        <div className="section-heading">
          <div>
            <p className="section-label">Current queue</p>
            <h2>{visibleItems.length} loaded</h2>
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              if (queueVisible) void ticketsQuery.refetch();
            }}
            disabled={!queueVisible || ticketsQuery.isFetching}
          >
            <RefreshCw
              className={ticketsQuery.isFetching ? "is-spinning" : undefined}
              aria-hidden="true"
            />
            Refresh
          </Button>
        </div>

        {viewSelection.kind === "invalid" ? (
          <FocusedError
            message="Clear the invalid saved-view link before loading this queue. No identifier or inline filter was sent to the backend."
            title="Saved-view link rejected"
          />
        ) : null}
        {selectedResolutionPending ? <TicketListSkeleton /> : null}
        {selectedView?.value.status === "archived" ? (
          <FocusedError
            message="Restore this private view to revalidate every dynamic definition pin before execution."
            title="Archived view is not executable"
          />
        ) : null}
        {queueVisible &&
        !selectedResolutionPending &&
        ticketsQuery.isPending ? (
          <TicketListSkeleton />
        ) : null}
        {queueVisible && ticketsQuery.isError ? (
          <div className="ticket-list-error">
            <FocusedError
              message={describeTicketingError(
                ticketsQuery.error,
                `The ${kindLabel(kind).toLowerCase()} queue could not be loaded.`,
              )}
              title={`${kindLabel(kind)} queue unavailable`}
            />
            <Button
              variant="outline"
              onClick={() => void ticketsQuery.refetch()}
            >
              Retry queue
            </Button>
          </div>
        ) : null}
        {queueVisible &&
        !ticketsQuery.isPending &&
        !ticketsQuery.isError &&
        visibleItems.length === 0 ? (
          <TicketEmpty kind={kind} canCreate={canCreate} />
        ) : null}
        {queueVisible && visibleItems.length > 0 ? (
          <>
            {visibleItems.every((item) => item.projection === "operator") ? (
              <TicketBulkControls
                availableActions={availableBulkActions}
                csrfToken={session.csrfToken}
                kind={kind}
                onClearSelection={() => {
                  setBulkTargets([]);
                  setBulkSelectionReset((current) => current + 1);
                }}
                onForbidden={authority.reload}
                onUnauthorized={() => clearSession(session.id)}
                query={bulkQuery}
                selectedTargets={bulkTargets}
                tenantId={tenantId}
              />
            ) : null}
            <TicketDataTable
              availableDynamicColumns={dynamicColumnCatalog}
              columnCatalogError={
                customFieldCatalogQuery.error ??
                slaCatalogQuery.error ??
                undefined
              }
              columnCatalogHasMore={
                customFieldCatalogQuery.hasNextPage ||
                slaCatalogQuery.hasNextPage
              }
              columnCatalogLoading={
                (canReadCustomFieldCatalog &&
                  customFieldCatalogQuery.isPending) ||
                (canReadSlaCatalog && slaCatalogQuery.isPending)
              }
              columnCatalogLoadingMore={
                customFieldCatalogQuery.isFetchingNextPage ||
                slaCatalogQuery.isFetchingNextPage
              }
              columns={tableColumns}
              items={visibleItems}
              kind={kind}
              onColumnsChange={handleColumnsChange}
              onLoadMoreColumns={() => {
                if (customFieldCatalogQuery.hasNextPage) {
                  void customFieldCatalogQuery.fetchNextPage();
                }
                if (slaCatalogQuery.hasNextPage) {
                  void slaCatalogQuery.fetchNextPage();
                }
              }}
              onColumnCatalogRequested={() => setColumnCatalogRequested(true)}
              onSelectionChange={handleBulkSelectionChange}
              selectionResetToken={bulkSelectionReset}
              selectionScope={`${tenantId}:${kind}:${serializedSearch}:${selectedViewScope}`}
            />
          </>
        ) : null}

        {queueVisible && ticketsQuery.hasNextPage ? (
          <Button
            className="ticket-load-more"
            variant="outline"
            onClick={() => void ticketsQuery.fetchNextPage()}
            disabled={ticketsQuery.isFetchingNextPage}
          >
            <ArrowDown aria-hidden="true" />
            {ticketsQuery.isFetchingNextPage
              ? "Loading next page…"
              : "Load next page"}
          </Button>
        ) : null}
      </section>
    </div>
  );
}

function TicketAuthorityLoading({
  kind,
}: {
  kind: TicketKind;
}): React.JSX.Element {
  return (
    <div className="content content--narrow" role="status">
      <section className="page-heading">
        <div>
          <p className="section-label">Live authorization</p>
          <h1>Checking {kindLabel(kind).toLowerCase()} authority…</h1>
          <p>
            The queue and private views remain closed until the active tenant
            projection is ready.
          </p>
        </div>
      </section>
    </div>
  );
}

function ticketFilterDraftFromURL(parameters: URLSearchParams): FilterDraft {
  const status = canonicalWorkflowStates(
    parameters.getAll("status").join(","),
  ).join(", ");
  return {
    customerVisible: knownValue(
      parameters.get("visibility"),
      customerVisibilityFilters,
      "all",
    ),
    priority: knownValue(parameters.get("priority"), ticketPriorities, "all"),
    queue: knownValue(parameters.get("queue"), ticketQueues, "all"),
    search: canonicalTicketSearch(parameters.get("search")),
    severity: knownValue(parameters.get("severity"), alertSeverities, "all"),
    sort: knownValue(parameters.get("sort"), ticketSorts, "updated_at_desc"),
    status,
  };
}

function ticketFiltersFromDraft(draft: FilterDraft): TicketListFilters {
  const search = canonicalTicketSearch(draft.search);
  const statuses = canonicalWorkflowStates(draft.status);
  return {
    limit: 30,
    sort: knownValue(draft.sort, ticketSorts, "updated_at_desc"),
    ...(search ? { search } : {}),
    ...(statuses.length > 0 ? { status: statuses } : {}),
    ...(draft.severity === "all" ? {} : { severity: [draft.severity] }),
    ...(draft.priority === "all" ? {} : { priority: [draft.priority] }),
    ...(draft.queue === "all" ? {} : { queue: draft.queue }),
    ...(draft.customerVisible === "all"
      ? {}
      : { customerVisible: draft.customerVisible === "customer" }),
  };
}

function ticketFilterURLFromDraft(draft: FilterDraft): URLSearchParams {
  const filters = ticketFiltersFromDraft(draft);
  const parameters = new URLSearchParams();
  if (filters.search) parameters.set("search", filters.search);
  if (filters.status?.length) {
    parameters.set("status", filters.status.join(","));
  }
  if (filters.severity?.[0]) {
    parameters.set("severity", filters.severity[0]);
  }
  if (filters.priority?.[0]) {
    parameters.set("priority", filters.priority[0]);
  }
  if (filters.queue) parameters.set("queue", filters.queue);
  if (draft.customerVisible !== "all") {
    parameters.set("visibility", draft.customerVisible);
  }
  if (filters.sort !== "updated_at_desc") {
    parameters.set("sort", filters.sort ?? "updated_at_desc");
  }
  return parameters;
}

function canonicalTicketSearch(value: string | null): string {
  return Array.from((value ?? "").trim())
    .slice(0, maximumSearchLength)
    .join("");
}

function canonicalWorkflowStates(value: string): string[] {
  return (parseStatusFilter(value) ?? [])
    .filter((state) => workflowStatePattern.test(state))
    .slice(0, maximumWorkflowStateFilters);
}

function knownValue<const T extends string, F extends string>(
  value: string | null,
  catalog: readonly T[],
  fallback: F,
): T | F {
  return catalog.find((candidate) => candidate === value) ?? fallback;
}

function bulkActionsForAuthority(
  kind: TicketKind,
  check: (
    permission: TenantPermissionKeyView,
    scope?: TenantAuthorizationScopeView,
  ) => boolean,
): TicketBulkAction[] {
  const result: TicketBulkAction[] = [];
  const transitionPermission =
    kind === "alert" ? "alert.update" : "case.transition";
  const assignmentPermission =
    kind === "alert" ? "alert.assign" : "case.transfer";
  const claimPermission = kind === "alert" ? "alert.claim" : "case.claim";
  if (hasAnyTicketPermission(check, transitionPermission)) {
    result.push("transition");
  }
  if (hasAnyTicketPermission(check, assignmentPermission)) {
    result.push("assign", "transfer");
  }
  if (hasAnyTicketPermission(check, claimPermission)) {
    result.push("claim", "release");
  }
  return result;
}

function sameBulkTargets(
  left: readonly TicketBulkTargetPin[],
  right: readonly TicketBulkTargetPin[],
): boolean {
  return (
    left.length === right.length &&
    left.every(
      (target, index) =>
        target.id === right[index]?.id &&
        target.expectedVersion === right[index]?.expectedVersion,
    )
  );
}

function uniqueDynamicColumnCatalog(
  items: readonly TicketDynamicColumnCatalogItem[],
): TicketDynamicColumnCatalogItem[] {
  const latestByIdentity = new Map<string, TicketDynamicColumnCatalogItem>();
  for (const item of items) {
    const identity = `${item.source}:${item.definitionId}`;
    const current = latestByIdentity.get(identity);
    if (
      current === undefined ||
      item.definitionVersion > current.definitionVersion
    ) {
      latestByIdentity.set(identity, item);
    }
  }
  return [...latestByIdentity.values()].toSorted((left, right) => {
    const source = left.source.localeCompare(right.source, "en");
    return source !== 0
      ? source
      : left.definitionLabel.localeCompare(right.definitionLabel, "en");
  });
}

function FilterSelect<T extends string>({
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
    <label className="ticket-filter-field">
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
          <option value={option} key={option}>
            {humanizeKey(option)}
          </option>
        ))}
      </select>
    </label>
  );
}

function TicketListSkeleton(): React.JSX.Element {
  return (
    <div className="ticket-list-skeleton" aria-label="Loading ticket queue">
      <span />
      <span />
      <span />
      <span />
    </div>
  );
}

function TicketEmpty({
  canCreate,
  kind,
}: {
  canCreate: boolean;
  kind: TicketKind;
}): React.JSX.Element {
  const Icon = kind === "alert" ? BellRing : BriefcaseBusiness;
  return (
    <div className="ticket-empty">
      <Icon aria-hidden="true" />
      <h3>No {kindLabelPlural(kind).toLowerCase()} match this queue.</h3>
      <p>
        Clear one or more filters, or refresh to request the current authorized
        projection from the server.
      </p>
      {canCreate ? (
        <Button asChild size="sm" variant="outline">
          <Link to={`/${kind === "alert" ? "alerts" : "cases"}/new`}>
            <Plus aria-hidden="true" /> Create {kindLabel(kind).toLowerCase()}
          </Link>
        </Button>
      ) : null}
    </div>
  );
}

function NoTenant({ kind }: { kind: TicketKind }): React.JSX.Element {
  return (
    <div className="content content--narrow">
      <section className="page-heading">
        <div>
          <p className="section-label">Tenant context required</p>
          <h1>Select a tenant first.</h1>
          <p>
            {kindLabelPlural(kind)} are tenant-owned. Choose an active tenant in
            the workspace switcher before opening this queue.
          </p>
        </div>
      </section>
    </div>
  );
}
