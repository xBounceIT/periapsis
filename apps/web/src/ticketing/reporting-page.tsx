import { useInfiniteQuery } from "@tanstack/react-query";
import type {
  SavedTicketView,
  TenantPermissionKey,
  TicketExportJobRequest,
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
import {
  Clock3,
  FileSpreadsheet,
  LoaderCircle,
  RefreshCw,
  ShieldCheck,
  ShieldX,
} from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";

import { useSession } from "../auth/session-context";
import { useTenantAuthority } from "../auth/tenant-authority-context";
import {
  describeTicketingError,
  TicketingApiError,
  type SavedTicketViewPageView,
  type TicketKind,
} from "../lib/ticketing-api";
import {
  defaultTicketTableColumns,
  inlineSavedViewSpec,
} from "./saved-view-model";
import { TicketExportControls } from "./ticket-export-controls";
import { useTicketingApi } from "./ticketing-context";
import {
  hasAllTicketPermissionsAtOneScope,
  hasAnyTicketPermission,
  kindLabel,
  kindLabelPlural,
} from "./ticketing-model";
// oxlint-disable-next-line import/no-unassigned-import -- Vite extracts this page-owned stylesheet.
import "./reporting-page.css";

interface SavedViewInventory {
  invalid: boolean;
  items: SavedTicketView[];
}

interface SavedViewInventoryBoundary {
  kind: TicketKind;
  ownerMembershipId: string;
  tenantId: string;
}

const allTicketsSource = {
  source: "inline",
  spec: inlineSavedViewSpec({}, defaultTicketTableColumns),
} as const satisfies TicketExportJobRequest["source"];

export function ReportingPage(): React.JSX.Element {
  const api = useTicketingApi();
  const { clearSession, session } = useSession();
  const authority = useTenantAuthority();
  const tenantId = session.activeTenantId;
  const [requestedKind, setRequestedKind] = useState<TicketKind>("alert");
  const [selectedViewId, setSelectedViewId] = useState<string>();
  const readAccess = {
    alert:
      authority.status === "ready" &&
      hasAnyTicketPermission(authority.hasPermission, "alert.read"),
    case:
      authority.status === "ready" &&
      hasAnyTicketPermission(authority.hasPermission, "case.read"),
  };
  const selectedKind: TicketKind = readAccess[requestedKind]
    ? requestedKind
    : readAccess.alert
      ? "alert"
      : "case";
  const canLoad = Boolean(tenantId) && readAccess[selectedKind];
  const readPermission = `${selectedKind}.read` as TenantPermissionKey;
  const commentReadPermission =
    `${selectedKind}.comment.read` as TenantPermissionKey;
  const privateCommentPermission =
    `${selectedKind}.comment.private` as TenantPermissionKey;
  const allowPublicComments = hasAllTicketPermissionsAtOneScope(
    authority.hasPermission,
    [readPermission, commentReadPermission],
  );
  const allowPrivateComments = hasAllTicketPermissionsAtOneScope(
    authority.hasPermission,
    [readPermission, commentReadPermission, privateCommentPermission],
  );

  const viewsQuery = useInfiniteQuery({
    enabled: canLoad,
    initialPageParam: undefined as string | undefined,
    queryKey: [
      "report-saved-ticket-views",
      authority.pairKey,
      authority.revision,
      tenantId,
      selectedKind,
    ],
    queryFn: ({ pageParam, signal }) =>
      api.listSavedTicketViews({
        ...(pageParam ? { after: pageParam } : {}),
        includeArchived: false,
        kind: selectedKind,
        signal,
        tenantId: tenantId!,
      }),
    getNextPageParam: (page, pages) =>
      page.nextCursor &&
      !pages
        .slice(0, -1)
        .some((candidate) => candidate.nextCursor === page.nextCursor)
        ? page.nextCursor
        : undefined,
    retry: false,
  });
  const inventory = useMemo(
    () =>
      mergeReportSavedViewPages(viewsQuery.data?.pages ?? [], {
        kind: selectedKind,
        ownerMembershipId: authority.authority?.membershipId ?? "",
        tenantId: tenantId ?? "",
      }),
    [
      authority.authority?.membershipId,
      selectedKind,
      tenantId,
      viewsQuery.data?.pages,
    ],
  );
  const selectedView = inventory.items.find(
    (view) => view.id === selectedViewId,
  );
  const selectedViewUnavailable =
    selectedViewId !== undefined &&
    !viewsQuery.isPending &&
    selectedView === undefined;
  const source = useMemo<TicketExportJobRequest["source"]>(
    () =>
      selectedView
        ? {
            source: "saved_view",
            savedView: {
              expectedRevision: selectedView.revision,
              expectedSpecSha256: selectedView.specSha256,
              id: selectedView.id,
            },
          }
        : allTicketsSource,
    [selectedView],
  );
  const sourceKey = JSON.stringify(source);
  const accessError =
    viewsQuery.error instanceof TicketingApiError &&
    (viewsQuery.error.status === 401 || viewsQuery.error.status === 403)
      ? viewsQuery.error
      : undefined;
  const handledAccessFailure = useRef<string | undefined>(undefined);

  useEffect(() => {
    setSelectedViewId(undefined);
  }, [authority.pairKey, authority.revision, selectedKind, tenantId]);

  useEffect(() => {
    if (viewsQuery.isSuccess) handledAccessFailure.current = undefined;
    if (!accessError) return;
    const failureKey = `${authority.pairKey}:${accessError.status}`;
    if (handledAccessFailure.current === failureKey) return;
    handledAccessFailure.current = failureKey;
    if (accessError.status === 401) clearSession(session.id);
    else authority.reload();
  }, [accessError, authority, clearSession, session.id, viewsQuery.isSuccess]);

  if (!tenantId) {
    return (
      <ReportingBoundary
        title="Select a tenant before opening Reports"
        detail="Reports are tenant-local. Choose an active tenant before any saved-view inventory or export request can be sent."
      />
    );
  }
  if (authority.status === "loading") return <ReportingSkeleton />;
  if (authority.status !== "ready" || (!readAccess.alert && !readAccess.case)) {
    return (
      <ReportingBoundary
        title="Reports are not available"
        detail="The current live authority does not grant Alert or Case read access. No reporting request was sent."
      />
    );
  }

  return (
    <div className="content reporting-page">
      <section className="page-heading" aria-labelledby="reporting-title">
        <div>
          <p className="section-label">Tenant operations</p>
          <h1 id="reporting-title">Reports</h1>
          <p>
            Generate a bounded CSV from all authorized tickets or an exact
            active saved view. Each job captures an immutable query snapshot and
            runs asynchronously.
          </p>
        </div>
        <Badge variant="outline">
          <FileSpreadsheet aria-hidden="true" /> Authorized CSV
        </Badge>
      </section>

      <section
        className="reporting-assurances"
        aria-labelledby="reporting-safeguards-title"
      >
        <h2 className="sr-only" id="reporting-safeguards-title">
          Export safeguards
        </h2>
        <Card>
          <CardHeader>
            <Clock3 aria-hidden="true" />
            <CardTitle aria-level={3} role="heading">
              Bounded retention
            </CardTitle>
            <CardDescription>
              Choose 15 minutes through 7 days. The worker enforces the row and
              artifact limits shown below.
            </CardDescription>
          </CardHeader>
        </Card>
        <Card>
          <CardHeader>
            <ShieldCheck aria-hidden="true" />
            <CardTitle aria-level={3} role="heading">
              Live reauthorization
            </CardTitle>
            <CardDescription>
              Queueing, status access, and every short-lived download are
              authorized again against the active tenant.
            </CardDescription>
          </CardHeader>
        </Card>
      </section>

      <Card>
        <CardHeader>
          <CardTitle aria-level={2} role="heading">
            Report source
          </CardTitle>
          <CardDescription>
            Only resource kinds exposed by the current live authority are
            selectable. Saved sources stay pinned to their exact revision and
            specification digest.
          </CardDescription>
        </CardHeader>
        <CardContent className="reporting-source-grid">
          <label htmlFor="report-kind">
            <span>Ticket type</span>
            <select
              id="report-kind"
              value={selectedKind}
              onChange={(event) => {
                const kind = event.target.value;
                if ((kind === "alert" || kind === "case") && readAccess[kind]) {
                  setRequestedKind(kind);
                }
              }}
            >
              {readAccess.alert ? <option value="alert">Alerts</option> : null}
              {readAccess.case ? <option value="case">Cases</option> : null}
            </select>
          </label>
          <label htmlFor="report-source">
            <span>Saved-view source</span>
            <select
              id="report-source"
              disabled={viewsQuery.isPending}
              value={selectedViewId ?? ""}
              onChange={(event) =>
                setSelectedViewId(event.target.value || undefined)
              }
            >
              <option value="">
                All authorized {kindLabelPlural(selectedKind)}
              </option>
              {selectedViewUnavailable ? (
                <option value={selectedViewId} disabled>
                  Selected saved view is unavailable
                </option>
              ) : null}
              {!inventory.invalid
                ? inventory.items.map((view) => (
                    <option key={view.id} value={view.id}>
                      {view.name}
                    </option>
                  ))
                : null}
            </select>
          </label>
          <div className="reporting-source-actions">
            {viewsQuery.hasNextPage ? (
              <Button
                type="button"
                size="sm"
                variant="ghost"
                disabled={viewsQuery.isFetchingNextPage}
                onClick={() => void viewsQuery.fetchNextPage()}
              >
                {viewsQuery.isFetchingNextPage ? (
                  <LoaderCircle className="is-spinning" aria-hidden="true" />
                ) : null}
                Load more saved views
              </Button>
            ) : null}
            {viewsQuery.isError && !accessError ? (
              <Button
                type="button"
                size="sm"
                variant="ghost"
                onClick={() => void viewsQuery.refetch()}
              >
                <RefreshCw aria-hidden="true" /> Retry saved views
              </Button>
            ) : null}
          </div>
        </CardContent>
      </Card>

      {viewsQuery.isPending ? (
        <p className="reporting-status" role="status">
          <LoaderCircle className="is-spinning" aria-hidden="true" /> Loading
          saved report sources…
        </p>
      ) : inventory.invalid ? (
        <p className="reporting-status reporting-status--error" role="alert">
          Saved-view inventory was rejected because its page sequence was not
          canonical. Only the inline all-{selectedKind} source remains usable.
        </p>
      ) : viewsQuery.isError ? (
        <p className="reporting-status reporting-status--error" role="alert">
          {describeTicketingError(
            viewsQuery.error,
            "Saved report sources are unavailable. The bounded inline source remains usable.",
          )}
        </p>
      ) : selectedView ? (
        <p className="reporting-status">
          {kindLabel(selectedKind)} source pinned to saved view revision{" "}
          {selectedView.revision}.
        </p>
      ) : (
        <p className="reporting-status">
          The inline source includes all{" "}
          {kindLabelPlural(selectedKind).toLowerCase()}
          currently visible to the resolved server-side scope.
        </p>
      )}

      {!accessError && !selectedViewUnavailable ? (
        <TicketExportControls
          key={`${authority.pairKey}:${authority.revision}:${selectedKind}:${sourceKey}`}
          allowPrivateComments={allowPrivateComments}
          allowPublicComments={allowPublicComments}
          csrfToken={session.csrfToken}
          kind={selectedKind}
          onForbidden={authority.reload}
          onUnauthorized={() => clearSession(session.id)}
          source={source}
          tenantId={tenantId}
        />
      ) : null}
    </div>
  );
}

export function mergeReportSavedViewPages(
  pages: readonly SavedTicketViewPageView[],
  boundary: SavedViewInventoryBoundary,
): SavedViewInventory {
  const items: SavedTicketView[] = [];
  let previousId: string | undefined;
  for (const page of pages) {
    for (const item of page.items) {
      if (
        item.status !== "active" ||
        item.kind !== boundary.kind ||
        item.ownerMembershipId !== boundary.ownerMembershipId ||
        item.tenantId !== boundary.tenantId ||
        (previousId !== undefined && previousId >= item.id)
      ) {
        return { invalid: true, items: [] };
      }
      items.push(item);
      previousId = item.id;
    }
  }
  return { invalid: false, items };
}

function ReportingBoundary({
  detail,
  title,
}: {
  detail: string;
  title: string;
}): React.JSX.Element {
  return (
    <div className="content content--narrow">
      <section className="page-heading" aria-labelledby="report-boundary-title">
        <p className="section-label">Tenant operations</p>
        <h1 id="report-boundary-title">{title}</h1>
        <p>{detail}</p>
      </section>
      <Card>
        <CardHeader>
          <ShieldX aria-hidden="true" />
          <CardTitle aria-level={2} role="heading">
            Deny-by-default boundary
          </CardTitle>
          <CardDescription>
            UI visibility never grants access to report data or artifacts.
          </CardDescription>
        </CardHeader>
      </Card>
    </div>
  );
}

function ReportingSkeleton(): React.JSX.Element {
  return (
    <div
      className="ticket-list-skeleton"
      aria-busy="true"
      aria-label="Loading Reports authority"
    >
      {Array.from({ length: 4 }, (_, index) => (
        <span key={index} />
      ))}
    </div>
  );
}
