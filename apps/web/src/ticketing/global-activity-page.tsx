import { Badge } from "@periapsis/ui/components/ui/badge";
import { Button } from "@periapsis/ui/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@periapsis/ui/components/ui/card";
import { useInfiniteQuery } from "@tanstack/react-query";
import {
  Activity,
  BellRing,
  BriefcaseBusiness,
  ChevronDown,
  ShieldX,
  UserRound,
} from "lucide-react";
import { useState } from "react";
import { Link } from "react-router";
import {
  mergeActivityPages,
  type OperatorActivity,
} from "./global-activity-page-model";

import { useSession } from "../auth/session-context";
import { useTenantAuthority } from "../auth/tenant-authority-context";
import { FocusedError } from "../components/focused-error";
import { TenantInstant } from "../lib/tenant-date-time-context";
import { describeTicketingError, type TicketKind } from "../lib/ticketing-api";
import { useTicketingApi } from "./ticketing-context";
import {
  hasAllTicketPermissionsAtOneScope,
  humanizeKey,
  kindLabel,
  kindLabelPlural,
} from "./ticketing-model";

function useGlobalActivityPageState() {
  const api = useTicketingApi();
  const { session } = useSession();
  const authority = useTenantAuthority();
  const tenantId = session.activeTenantId;
  const [requestedKind, setRequestedKind] = useState<TicketKind>("alert");
  const access = {
    alert: hasAllTicketPermissionsAtOneScope(authority.hasPermission, [
      "alert.read",
      "alert.activity.read",
    ]),
    case: hasAllTicketPermissionsAtOneScope(authority.hasPermission, [
      "case.read",
      "case.activity.read",
    ]),
  };
  const selectedKind = access[requestedKind]
    ? requestedKind
    : access.alert
      ? "alert"
      : "case";
  const canLoad =
    authority.status === "ready" && Boolean(tenantId) && access[selectedKind];
  const feed = useInfiniteQuery({
    enabled: canLoad,
    initialPageParam: undefined as string | undefined,
    queryFn: ({ pageParam, signal }) =>
      api.listActivityFeed(selectedKind, tenantId!, pageParam, signal),
    queryKey: [
      "tenant-activity-feed",
      selectedKind,
      tenantId,
      authority.revision,
    ],
    getNextPageParam: (page) => page.nextCursor,
  });
  const projection = mergeActivityPages(feed.data?.pages ?? []);
  return {
    api,
    session,
    authority,
    tenantId,
    requestedKind,
    setRequestedKind,
    access,
    selectedKind,
    canLoad,
    feed,
    projection,
  };
}

export function GlobalActivityPage(): React.JSX.Element {
  const state = useGlobalActivityPageState();
  const {
    authority,
    tenantId,
    setRequestedKind,
    access,
    selectedKind,
    feed,
    projection,
  } = state;
  if (!tenantId) {
    return (
      <ActivityBoundary
        title="Select a tenant before opening Activity"
        detail="The global feed is deliberately tenant-local. Choose a tenant so the API and PostgreSQL can enforce its live authorization boundary."
      />
    );
  }
  if (authority.status === "loading") return <ActivitySkeleton />;
  if (authority.status !== "ready" || (!access.alert && !access.case)) {
    return (
      <ActivityBoundary
        title="Activity is not available"
        detail="The current live authority does not expose a matching ticket read and activity-read path. No feed request was sent."
      />
    );
  }

  return (
    <div className="content global-activity-page">
      <section className="page-heading" aria-labelledby="global-activity-title">
        <div>
          <p className="section-label">Tenant operations</p>
          <h1 id="global-activity-title">Activity</h1>
          <p>
            Follow user-facing domain events across the active tenant. Resource
            authorization is applied before each newest-first page is built; the
            immutable security record remains in Audit.
          </p>
        </div>
        <Badge variant="outline">
          <Activity aria-hidden="true" /> Live authorized feed
        </Badge>
      </section>

      {access.alert && access.case ? (
        <div className="activity-feed-switcher" aria-label="Activity resource">
          <Button
            aria-pressed={selectedKind === "alert"}
            onClick={() => setRequestedKind("alert")}
            type="button"
            variant={selectedKind === "alert" ? "default" : "outline"}
          >
            <BellRing aria-hidden="true" /> Alerts
          </Button>
          <Button
            aria-pressed={selectedKind === "case"}
            onClick={() => setRequestedKind("case")}
            type="button"
            variant={selectedKind === "case" ? "default" : "outline"}
          >
            <BriefcaseBusiness aria-hidden="true" /> Cases
          </Button>
        </div>
      ) : null}

      <GlobalActivityFeed
        feed={feed}
        projection={projection}
        selectedKind={selectedKind}
      />
    </div>
  );
}

function ActivityFeedItem({
  activity,
  index,
}: {
  activity: OperatorActivity;
  index: number;
}): React.JSX.Element {
  const kind = activity.resourceKind;
  return (
    <li>
      <span className="ticket-activity-rail__node" aria-hidden="true">
        {index + 1}
      </span>
      <article>
        <header>
          <div>
            <small>{humanizeKey(activity.kind)}</small>
            <strong>{activity.summary}</strong>
          </div>
          <Badge variant="secondary">{kindLabel(kind)}</Badge>
        </header>
        <p>
          <UserRound aria-hidden="true" /> {activity.actor.displayName}
        </p>
        <TenantInstant precision="second" value={activity.occurredAt} />
        <Button asChild size="sm" variant="ghost">
          <Link
            to={`/${kind === "alert" ? "alerts" : "cases"}/${activity.resourceId}`}
          >
            Open {kindLabel(kind)}
          </Link>
        </Button>
      </article>
    </li>
  );
}

function ActivityBoundary({
  detail,
  title,
}: {
  detail: string;
  title: string;
}): React.JSX.Element {
  return (
    <div className="content content--narrow">
      <section
        className="page-heading"
        aria-labelledby="activity-boundary-title"
      >
        <p className="section-label">Tenant operations</p>
        <h1 id="activity-boundary-title">{title}</h1>
        <p>{detail}</p>
      </section>
      <Card>
        <CardHeader>
          <ShieldX aria-hidden="true" />
          <CardTitle>Deny-by-default boundary</CardTitle>
          <CardDescription>
            UI visibility never grants access to activity data.
          </CardDescription>
        </CardHeader>
      </Card>
    </div>
  );
}

function ActivitySkeleton({
  compact = false,
}: {
  compact?: boolean;
}): React.JSX.Element {
  return (
    <div
      className="ticket-list-skeleton"
      aria-busy="true"
      aria-label="Loading activity"
    >
      {Array.from({ length: compact ? 3 : 5 }, (_, index) => (
        <span key={index} />
      ))}
    </div>
  );
}

interface GlobalActivityFeedProps {
  feed: ReturnType<typeof useGlobalActivityPageState>["feed"];
  projection: ReturnType<typeof mergeActivityPages>;
  selectedKind: TicketKind;
}

function GlobalActivityFeed({
  feed,
  projection,
  selectedKind,
}: GlobalActivityFeedProps): React.JSX.Element {
  return (
    <Card className="activity-feed-card">
      <CardHeader>
        <CardTitle>{kindLabelPlural(selectedKind)} activity</CardTitle>
        <CardDescription>
          Events from {kindLabelPlural(selectedKind).toLowerCase()} currently
          visible through the same live read and activity scopes.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {feed.isPending ? <ActivitySkeleton compact /> : null}
        {feed.isError ? (
          <FocusedError
            title="Activity feed unavailable"
            message={describeTicketingError(
              feed.error,
              "The current authorized activity page could not be loaded.",
            )}
          />
        ) : null}
        {projection.invalid ? (
          <FocusedError
            title="Activity feed rejected"
            message="The server returned a duplicate or non-monotonic activity page. No ambiguous feed was rendered."
          />
        ) : null}
        {!feed.isPending &&
        !feed.isError &&
        !projection.invalid &&
        projection.items.length === 0 ? (
          <div className="global-search-empty">
            <strong>No visible activity yet</strong>
            <p>
              No {kindLabelPlural(selectedKind).toLowerCase()} events are
              present in the current authorized projection.
            </p>
          </div>
        ) : null}
        {!projection.invalid && projection.items.length > 0 ? (
          <ol className="ticket-activity-rail">
            {projection.items.map((item, index) => (
              <ActivityFeedItem activity={item} index={index} key={item.id} />
            ))}
          </ol>
        ) : null}
        {feed.hasNextPage && !projection.invalid ? (
          <Button
            disabled={feed.isFetchingNextPage}
            onClick={() => void feed.fetchNextPage()}
            type="button"
            variant="outline"
          >
            <ChevronDown aria-hidden="true" />
            {feed.isFetchingNextPage ? "Loading…" : "Load older activity"}
          </Button>
        ) : null}
      </CardContent>
    </Card>
  );
}
