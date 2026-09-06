import type {
  TicketBulkQuerySourceRequest,
  TicketBulkTargetPin,
  TicketExportJobRequest,
} from "@periapsis/contracts";
import { Button } from "@periapsis/ui/components/ui/button";
import { Input } from "@periapsis/ui/components/ui/input";
import {
  useInfiniteQuery,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
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
import { TenantRequiredPage } from "../components/tenant-required-page";

import { useSession } from "../auth/session-context";
import { useTenantAuthority } from "../auth/tenant-authority-context";
import { FocusedError } from "../components/focused-error";
import { ServerDenied } from "../components/server-denied";
import type {
  TenantAuthorizationScopeView,
  TenantPermissionKeyView,
} from "../lib/phase-two-types";
import {
  TicketColumnCatalogApiError,
  type TicketDynamicColumnCatalogItem,
} from "../lib/ticket-column-catalog-api";
import {
  TicketingApiError,
  describeTicketingError,
  type TicketKind,
  type TicketListFilters,
} from "../lib/ticketing-api";
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
import {
  TicketBulkControls,
  type TicketBulkAction,
} from "./ticket-bulk-controls";
import { useTicketColumnCatalogApi } from "./ticket-column-catalog-context";
import { TicketDataTable } from "./ticket-data-table";
import { TicketExportControls } from "./ticket-export-controls";
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

function useTicketListPageState({ kind }: TicketListPageProps) {
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
  const {
    createPermission,
    readPermission,
    canCreate,
    canRead,
    liveReadAuthority,
    allowPublicExportComments,
    allowPrivateExportComments,
    canReadSlaCatalog,
    canReadCustomFieldCatalog,
  } = ticketListPermissions(kind, authority);
  const availableBulkActions = useMemo(
    () => bulkActionsForAuthority(kind, authority.hasPermission),
    [authority.hasPermission, kind],
  );
  const [previousDraft, setPreviousDraft] = useState(committedDraft);
  if (previousDraft !== committedDraft) {
    setPreviousDraft(committedDraft);
    setDraft(committedDraft);
  }
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
    getNextPageParam: nextUnseenPageCursor,
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
  const {
    customFieldCatalogQuery,
    slaCatalogQuery,
    setColumnCatalogRequested,
  } = useTicketColumnCatalogs({
    columnCatalogApi,
    tenantId,
    kind,
    liveReadAuthority,
    canReadCustomFieldCatalog,
    canReadSlaCatalog,
  });
  const selectedView = selectedViewQuery.data;
  const selectedViewScope = selectedView
    ? `${selectedView.value.id}:${selectedView.value.revision}:${selectedView.value.specSha256}`
    : viewSelection.kind;
  const { tableColumns, setTableColumns, handleColumnsChange } =
    useSavedViewTableColumns(selectedView, selectedViewScope);
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
    queryFn: ({ pageParam, signal }) =>
      loadTicketListPage(
        api,
        kind,
        tenantId!,
        effectiveFilters,
        selectedView,
        pageParam,
        signal,
      ),
    getNextPageParam: nextUnseenPageCursor,
  });
  useTicketListAccessError({
    selectedViewQuery,
    viewsQuery,
    ticketsQuery,
    customFieldCatalogQuery,
    slaCatalogQuery,
    clearSession,
    session,
    authority,
  });
  const {
    bulkTargets,
    setBulkTargets,
    bulkSelectionReset,
    setBulkSelectionReset,
    handleBulkSelectionChange,
  } = useTicketBulkSelection(
    JSON.stringify([kind, selectedViewScope, serializedSearch, tenantId]),
  );
  return {
    kind,
    api,
    columnCatalogApi,
    clearSession,
    session,
    authority,
    queryClient,
    tenantId,
    searchParameters,
    setSearchParameters,
    serializedSearch,
    viewSelection,
    committedDraft,
    draft,
    setDraft,
    filters,
    tableColumns,
    setTableColumns,
    bulkTargets,
    setBulkTargets,
    bulkSelectionReset,
    setBulkSelectionReset,
    setColumnCatalogRequested,
    createPermission,
    readPermission,
    canCreate,
    canRead,
    liveReadAuthority,
    availableBulkActions,
    allowPublicExportComments,
    allowPrivateExportComments,
    canReadSlaCatalog,
    canReadCustomFieldCatalog,
    viewsQuery,
    selectedViewId,
    selectedViewQuery,
    customFieldCatalogQuery,
    slaCatalogQuery,
    selectedView,
    selectedViewScope,
    handleColumnsChange,
    currentSpec,
    bulkQuery,
    exportSource,
    selectedCanExecute,
    queueExecutable,
    selectedResolutionPending,
    effectiveFilters,
    ticketsQuery,
    handleBulkSelectionChange,
  };
}

function createTicketListPageActions({
  kind,
  queryClient,
  tenantId,
  setSearchParameters,
  draft,
  setDraft,
  selectedViewId,
}: ReturnType<typeof useTicketListPageState>) {
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
  return { applyFilters, resetFilters, selectView, reloadViews };
}

export function TicketListPage(props: TicketListPageProps): React.JSX.Element {
  const state = useTicketListPageState(props);
  const {
    kind,
    api,
    clearSession,
    session,
    authority,
    queryClient,
    tenantId,
    serializedSearch,
    viewSelection,
    draft,
    setDraft,
    tableColumns,
    bulkTargets,
    setBulkTargets,
    bulkSelectionReset,
    setBulkSelectionReset,
    setColumnCatalogRequested,
    canCreate,
    liveReadAuthority,
    availableBulkActions,
    allowPublicExportComments,
    allowPrivateExportComments,
    canReadSlaCatalog,
    canReadCustomFieldCatalog,
    viewsQuery,
    selectedViewQuery,
    customFieldCatalogQuery,
    slaCatalogQuery,
    selectedView,
    selectedViewScope,
    handleColumnsChange,
    currentSpec,
    bulkQuery,
    exportSource,
    selectedResolutionPending,
    ticketsQuery,
    handleBulkSelectionChange,
  } = state;
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
  const {
    views,
    queueVisible,
    visibleItems,
    dynamicColumnCatalog,
    queuePending,
  } = ticketListProjection(state);
  const { applyFilters, resetFilters, selectView, reloadViews } =
    createTicketListPageActions(state);
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

      <TicketListFilters
        applyFilters={applyFilters}
        draft={draft}
        kind={kind}
        resetFilters={resetFilters}
        setDraft={setDraft}
        viewSelection={viewSelection}
      />

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

      <TicketListResults
        authority={authority}
        availableBulkActions={availableBulkActions}
        bulkQuery={bulkQuery}
        bulkSelectionReset={bulkSelectionReset}
        bulkTargets={bulkTargets}
        canCreate={canCreate}
        canReadCustomFieldCatalog={canReadCustomFieldCatalog}
        canReadSlaCatalog={canReadSlaCatalog}
        clearSession={clearSession}
        customFieldCatalogQuery={customFieldCatalogQuery}
        dynamicColumnCatalog={dynamicColumnCatalog}
        handleBulkSelectionChange={handleBulkSelectionChange}
        handleColumnsChange={handleColumnsChange}
        kind={kind}
        queuePending={queuePending}
        queueVisible={queueVisible}
        selectedResolutionPending={selectedResolutionPending}
        selectedView={selectedView}
        selectedViewScope={selectedViewScope}
        serializedSearch={serializedSearch}
        session={session}
        setBulkSelectionReset={setBulkSelectionReset}
        setBulkTargets={setBulkTargets}
        setColumnCatalogRequested={setColumnCatalogRequested}
        slaCatalogQuery={slaCatalogQuery}
        tableColumns={tableColumns}
        tenantId={tenantId}
        ticketsQuery={ticketsQuery}
        viewSelection={viewSelection}
        visibleItems={visibleItems}
      />
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
    <TenantRequiredPage>
      {kindLabelPlural(kind)} are tenant-owned. Choose an active tenant in the
      workspace switcher before opening this queue.
    </TenantRequiredPage>
  );
}

interface TicketListResultsProps {
  authority: ReturnType<typeof useTicketListPageState>["authority"];
  availableBulkActions: ReturnType<
    typeof useTicketListPageState
  >["availableBulkActions"];
  bulkQuery: ReturnType<typeof useTicketListPageState>["bulkQuery"];
  bulkSelectionReset: ReturnType<
    typeof useTicketListPageState
  >["bulkSelectionReset"];
  bulkTargets: ReturnType<typeof useTicketListPageState>["bulkTargets"];
  canCreate: ReturnType<typeof useTicketListPageState>["canCreate"];
  canReadCustomFieldCatalog: ReturnType<
    typeof useTicketListPageState
  >["canReadCustomFieldCatalog"];
  canReadSlaCatalog: ReturnType<
    typeof useTicketListPageState
  >["canReadSlaCatalog"];
  clearSession: ReturnType<typeof useTicketListPageState>["clearSession"];
  customFieldCatalogQuery: ReturnType<
    typeof useTicketListPageState
  >["customFieldCatalogQuery"];
  dynamicColumnCatalog: TicketDynamicColumnCatalogItem[];
  handleBulkSelectionChange: ReturnType<
    typeof useTicketListPageState
  >["handleBulkSelectionChange"];
  handleColumnsChange: ReturnType<
    typeof useTicketListPageState
  >["handleColumnsChange"];
  kind: ReturnType<typeof useTicketListPageState>["kind"];
  queuePending: boolean;
  queueVisible: boolean;
  selectedResolutionPending: ReturnType<
    typeof useTicketListPageState
  >["selectedResolutionPending"];
  selectedView: ReturnType<typeof useTicketListPageState>["selectedView"];
  selectedViewScope: ReturnType<
    typeof useTicketListPageState
  >["selectedViewScope"];
  serializedSearch: ReturnType<
    typeof useTicketListPageState
  >["serializedSearch"];
  session: ReturnType<typeof useTicketListPageState>["session"];
  setBulkSelectionReset: ReturnType<
    typeof useTicketListPageState
  >["setBulkSelectionReset"];
  setBulkTargets: ReturnType<typeof useTicketListPageState>["setBulkTargets"];
  setColumnCatalogRequested: ReturnType<
    typeof useTicketListPageState
  >["setColumnCatalogRequested"];
  slaCatalogQuery: ReturnType<typeof useTicketListPageState>["slaCatalogQuery"];
  tableColumns: ReturnType<typeof useTicketListPageState>["tableColumns"];
  tenantId: NonNullable<ReturnType<typeof useTicketListPageState>["tenantId"]>;
  ticketsQuery: ReturnType<typeof useTicketListPageState>["ticketsQuery"];
  viewSelection: ReturnType<typeof useTicketListPageState>["viewSelection"];
  visibleItems: NonNullable<
    ReturnType<typeof useTicketListPageState>["ticketsQuery"]["data"]
  >["pages"][number]["items"];
}

function TicketListResults({
  authority,
  availableBulkActions,
  bulkQuery,
  bulkSelectionReset,
  bulkTargets,
  canCreate,
  canReadCustomFieldCatalog,
  canReadSlaCatalog,
  clearSession,
  customFieldCatalogQuery,
  dynamicColumnCatalog,
  handleBulkSelectionChange,
  handleColumnsChange,
  kind,
  queuePending,
  queueVisible,
  selectedResolutionPending,
  selectedView,
  selectedViewScope,
  serializedSearch,
  session,
  setBulkSelectionReset,
  setBulkTargets,
  setColumnCatalogRequested,
  slaCatalogQuery,
  tableColumns,
  tenantId,
  ticketsQuery,
  viewSelection,
  visibleItems,
}: TicketListResultsProps): React.JSX.Element {
  return (
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

      <TicketQueueStatus
        canCreate={canCreate}
        kind={kind}
        queueVisible={queueVisible}
        selectedResolutionPending={selectedResolutionPending}
        selectedView={selectedView}
        ticketsQuery={ticketsQuery}
        viewSelection={viewSelection}
        visibleItems={visibleItems}
      />
      {queueVisible && visibleItems.length > 0 ? (
        <TicketQueueTable
          authority={authority}
          availableBulkActions={availableBulkActions}
          bulkQuery={bulkQuery}
          bulkSelectionReset={bulkSelectionReset}
          bulkTargets={bulkTargets}
          canReadCustomFieldCatalog={canReadCustomFieldCatalog}
          canReadSlaCatalog={canReadSlaCatalog}
          clearSession={clearSession}
          customFieldCatalogQuery={customFieldCatalogQuery}
          dynamicColumnCatalog={dynamicColumnCatalog}
          handleBulkSelectionChange={handleBulkSelectionChange}
          handleColumnsChange={handleColumnsChange}
          kind={kind}
          selectedViewScope={selectedViewScope}
          serializedSearch={serializedSearch}
          session={session}
          setBulkSelectionReset={setBulkSelectionReset}
          setBulkTargets={setBulkTargets}
          setColumnCatalogRequested={setColumnCatalogRequested}
          slaCatalogQuery={slaCatalogQuery}
          tableColumns={tableColumns}
          tenantId={tenantId}
          visibleItems={visibleItems}
        />
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
  );
}

interface TicketListFiltersProps {
  applyFilters: ReturnType<typeof createTicketListPageActions>["applyFilters"];
  draft: ReturnType<typeof useTicketListPageState>["draft"];
  kind: ReturnType<typeof useTicketListPageState>["kind"];
  resetFilters: ReturnType<typeof createTicketListPageActions>["resetFilters"];
  setDraft: ReturnType<typeof useTicketListPageState>["setDraft"];
  viewSelection: ReturnType<typeof useTicketListPageState>["viewSelection"];
}

function TicketListFilters({
  applyFilters,
  draft,
  kind,
  resetFilters,
  setDraft,
  viewSelection,
}: TicketListFiltersProps): React.JSX.Element {
  return (
    <form className="ticket-filter-panel" onSubmit={applyFilters} role="search">
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
        <Button type="button" size="sm" variant="ghost" onClick={resetFilters}>
          Reset
        </Button>
      </div>
      {viewSelection.kind === "selected" ? (
        <p className="ticket-filter-panel__saved-view-hint">
          Applying these queue filters switches back to an unsaved current view.
        </p>
      ) : null}
    </form>
  );
}

function nextUnseenPageCursor<T extends { nextCursor?: string }>(
  page: T,
  pages: readonly T[],
): string | undefined {
  if (!page.nextCursor) return undefined;
  return pages
    .slice(0, -1)
    .some((candidate) => candidate.nextCursor === page.nextCursor)
    ? undefined
    : page.nextCursor;
}

function useTicketBulkSelection(bulkScope: string) {
  const [bulkTargets, setBulkTargets] = useState<TicketBulkTargetPin[]>([]);
  const [bulkSelectionReset, setBulkSelectionReset] = useState(0);
  const [previousBulkScope, setPreviousBulkScope] = useState(bulkScope);
  if (previousBulkScope !== bulkScope) {
    setPreviousBulkScope(bulkScope);
    setBulkTargets([]);
    setBulkSelectionReset((current) => current + 1);
  }
  const handleBulkSelectionChange = useCallback(
    (next: TicketBulkTargetPin[]) => {
      setBulkTargets((current) =>
        sameBulkTargets(current, next) ? current : next,
      );
    },
    [],
  );

  return {
    bulkTargets,
    setBulkTargets,
    bulkSelectionReset,
    setBulkSelectionReset,
    handleBulkSelectionChange,
  };
}

function useSavedViewTableColumns(
  selectedView:
    | Awaited<
        ReturnType<ReturnType<typeof useTicketingApi>["getSavedTicketView"]>
      >
    | undefined,
  selectedViewScope: string,
) {
  const [tableColumns, setTableColumns] = useState<TicketTableColumnSpec[]>(
    () => defaultTicketTableColumns.map((column) => ({ ...column })),
  );
  const [previousViewScope, setPreviousViewScope] = useState<
    string | undefined
  >(undefined);
  if (previousViewScope !== selectedViewScope) {
    setPreviousViewScope(selectedViewScope);
    const next = selectedView
      ? tableColumnsFromSavedView(selectedView.value.spec.columns)
      : defaultTicketTableColumns.map((column) => ({ ...column }));
    setTableColumns((current) =>
      sameTableColumns(current, next) ? current : next,
    );
  }
  const handleColumnsChange = useCallback((next: TicketTableColumnSpec[]) => {
    setTableColumns((current) =>
      sameTableColumns(current, next) ? current : next,
    );
  }, []);

  return { tableColumns, setTableColumns, handleColumnsChange };
}

async function loadTicketListPage(
  api: ReturnType<typeof useTicketingApi>,
  kind: TicketKind,
  tenantId: string,
  effectiveFilters: TicketListFilters,
  selectedView:
    | Awaited<
        ReturnType<ReturnType<typeof useTicketingApi>["getSavedTicketView"]>
      >
    | undefined,
  pageParam: string | undefined,
  signal: AbortSignal,
) {
  const page = await api.listTickets(
    kind,
    tenantId,
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
}

interface TicketQueueStatusProps {
  canCreate: ReturnType<typeof useTicketListPageState>["canCreate"];
  kind: ReturnType<typeof useTicketListPageState>["kind"];
  queueVisible: TicketListResultsProps["queueVisible"];
  selectedResolutionPending: ReturnType<
    typeof useTicketListPageState
  >["selectedResolutionPending"];
  selectedView: ReturnType<typeof useTicketListPageState>["selectedView"];
  ticketsQuery: ReturnType<typeof useTicketListPageState>["ticketsQuery"];
  viewSelection: ReturnType<typeof useTicketListPageState>["viewSelection"];
  visibleItems: TicketListResultsProps["visibleItems"];
}

function TicketQueueStatus({
  canCreate,
  kind,
  queueVisible,
  selectedResolutionPending,
  selectedView,
  ticketsQuery,
  viewSelection,
  visibleItems,
}: TicketQueueStatusProps): React.JSX.Element {
  return (
    <>
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
      {queueVisible && !selectedResolutionPending && ticketsQuery.isPending ? (
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
          <Button variant="outline" onClick={() => void ticketsQuery.refetch()}>
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
    </>
  );
}

interface TicketQueueTableProps {
  authority: TicketListResultsProps["authority"];
  availableBulkActions: TicketListResultsProps["availableBulkActions"];
  bulkQuery: TicketListResultsProps["bulkQuery"];
  bulkSelectionReset: TicketListResultsProps["bulkSelectionReset"];
  bulkTargets: TicketListResultsProps["bulkTargets"];
  canReadCustomFieldCatalog: TicketListResultsProps["canReadCustomFieldCatalog"];
  canReadSlaCatalog: TicketListResultsProps["canReadSlaCatalog"];
  clearSession: TicketListResultsProps["clearSession"];
  customFieldCatalogQuery: TicketListResultsProps["customFieldCatalogQuery"];
  dynamicColumnCatalog: TicketListResultsProps["dynamicColumnCatalog"];
  handleBulkSelectionChange: TicketListResultsProps["handleBulkSelectionChange"];
  handleColumnsChange: TicketListResultsProps["handleColumnsChange"];
  kind: TicketListResultsProps["kind"];
  selectedViewScope: TicketListResultsProps["selectedViewScope"];
  serializedSearch: TicketListResultsProps["serializedSearch"];
  session: TicketListResultsProps["session"];
  setBulkSelectionReset: TicketListResultsProps["setBulkSelectionReset"];
  setBulkTargets: TicketListResultsProps["setBulkTargets"];
  setColumnCatalogRequested: TicketListResultsProps["setColumnCatalogRequested"];
  slaCatalogQuery: TicketListResultsProps["slaCatalogQuery"];
  tableColumns: TicketListResultsProps["tableColumns"];
  tenantId: TicketListResultsProps["tenantId"];
  visibleItems: TicketListResultsProps["visibleItems"];
}

function TicketQueueTable({
  authority,
  availableBulkActions,
  bulkQuery,
  bulkSelectionReset,
  bulkTargets,
  canReadCustomFieldCatalog,
  canReadSlaCatalog,
  clearSession,
  customFieldCatalogQuery,
  dynamicColumnCatalog,
  handleBulkSelectionChange,
  handleColumnsChange,
  kind,
  selectedViewScope,
  serializedSearch,
  session,
  setBulkSelectionReset,
  setBulkTargets,
  setColumnCatalogRequested,
  slaCatalogQuery,
  tableColumns,
  tenantId,
  visibleItems,
}: TicketQueueTableProps): React.JSX.Element {
  return (
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
          customFieldCatalogQuery.error ?? slaCatalogQuery.error ?? undefined
        }
        columnCatalogHasMore={
          customFieldCatalogQuery.hasNextPage || slaCatalogQuery.hasNextPage
        }
        columnCatalogLoading={
          (canReadCustomFieldCatalog && customFieldCatalogQuery.isPending) ||
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
  );
}

function ticketListProjection({
  ticketsQuery,
  viewsQuery,
  viewSelection,
  queueExecutable,
  selectedViewQuery,
  customFieldCatalogQuery,
  slaCatalogQuery,
  selectedResolutionPending,
}: ReturnType<typeof useTicketListPageState>) {
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
  return {
    views,
    queueVisible,
    visibleItems,
    dynamicColumnCatalog,
    queuePending,
  };
}

function useTicketColumnCatalogs({
  columnCatalogApi,
  tenantId,
  kind,
  liveReadAuthority,
  canReadCustomFieldCatalog,
  canReadSlaCatalog,
}: {
  columnCatalogApi: ReturnType<typeof useTicketColumnCatalogApi>;
  tenantId: string | undefined;
  kind: TicketKind;
  liveReadAuthority: boolean;
  canReadCustomFieldCatalog: boolean;
  canReadSlaCatalog: boolean;
}) {
  const [columnCatalogRequested, setColumnCatalogRequested] = useState(false);
  const catalogScope = JSON.stringify([kind, tenantId]);
  const [previousCatalogScope, setPreviousCatalogScope] =
    useState(catalogScope);
  if (previousCatalogScope !== catalogScope) {
    setPreviousCatalogScope(catalogScope);
    setColumnCatalogRequested(false);
  }
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
    getNextPageParam: nextUnseenPageCursor,
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
    getNextPageParam: nextUnseenPageCursor,
  });
  return {
    customFieldCatalogQuery,
    slaCatalogQuery,
    setColumnCatalogRequested,
  };
}

function useTicketListAccessError({
  selectedViewQuery,
  viewsQuery,
  ticketsQuery,
  customFieldCatalogQuery,
  slaCatalogQuery,
  clearSession,
  session,
  authority,
}: Pick<
  ReturnType<typeof useTicketListPageState>,
  | "selectedViewQuery"
  | "viewsQuery"
  | "ticketsQuery"
  | "customFieldCatalogQuery"
  | "slaCatalogQuery"
  | "clearSession"
  | "session"
  | "authority"
>) {
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
}

function ticketListPermissions(
  kind: TicketKind,
  authority: ReturnType<typeof useTenantAuthority>,
) {
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
  return {
    createPermission,
    readPermission,
    canCreate,
    canRead,
    liveReadAuthority,
    allowPublicExportComments,
    allowPrivateExportComments,
    canReadSlaCatalog,
    canReadCustomFieldCatalog,
  };
}
