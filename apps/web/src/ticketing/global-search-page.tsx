import { useQueries } from "@tanstack/react-query";
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
import { BellRing, BriefcaseBusiness, Search, ShieldX } from "lucide-react";
import { useEffect, useState, type FormEvent } from "react";
import { Link, useSearchParams } from "react-router";

import { useSession } from "../auth/session-context";
import { useTenantAuthority } from "../auth/tenant-authority-context";
import { FocusedError } from "../components/focused-error";
import { TenantInstant } from "../lib/tenant-date-time-context";
import {
  describeTicketingError,
  type TicketKind,
  type TicketPage,
  type TicketProjection,
} from "../lib/ticketing-api";
import { useTicketingApi } from "./ticketing-context";
import {
  hasAnyTicketPermission,
  humanizeKey,
  kindLabelPlural,
  ticketNumber,
} from "./ticketing-model";

const searchParameter = "q";
const maximumSearchLength = 200;

interface SearchSurface {
  canRead: boolean;
  icon: React.JSX.Element;
  kind: TicketKind;
}

const surfaces: readonly Omit<SearchSurface, "canRead">[] = [
  {
    icon: <BellRing aria-hidden="true" />,
    kind: "alert",
  },
  {
    icon: <BriefcaseBusiness aria-hidden="true" />,
    kind: "case",
  },
] as const;

export function GlobalSearchPage(): React.JSX.Element {
  const api = useTicketingApi();
  const { session } = useSession();
  const authority = useTenantAuthority();
  const tenantId = session.activeTenantId;
  const [parameters, setParameters] = useSearchParams();
  const committedQuery = canonicalSearch(parameters.get(searchParameter));
  const [draft, setDraft] = useState(committedQuery);
  const readableSurfaces: SearchSurface[] = surfaces.map((surface) => ({
    ...surface,
    canRead: hasAnyTicketPermission(
      authority.hasPermission,
      surface.kind === "alert" ? "alert.read" : "case.read",
    ),
  }));
  const hasReadableSurface = readableSurfaces.some(
    (surface) => surface.canRead,
  );

  useEffect(() => setDraft(committedQuery), [committedQuery]);

  const results = useQueries({
    queries: readableSurfaces.map((surface) => ({
      enabled:
        authority.status === "ready" &&
        surface.canRead &&
        Boolean(tenantId) &&
        committedQuery.length > 0,
      queryFn: ({ signal }: { signal: AbortSignal }) =>
        api.listTickets(
          surface.kind,
          tenantId!,
          {
            limit: 20,
            search: committedQuery,
            sort: "updated_at_desc",
          },
          signal,
        ),
      queryKey: [
        "global-search",
        surface.kind,
        tenantId,
        committedQuery,
        authority.revision,
      ],
    })),
  });

  function submit(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault();
    const query = canonicalSearch(draft);
    setParameters(query ? { [searchParameter]: query } : {}, { replace: true });
  }

  if (!tenantId) {
    return (
      <SearchBoundary
        title="Select a tenant before searching"
        detail="Global search is deliberately tenant-local. Choose a tenant so the API can evaluate its live permissions and PostgreSQL RLS context."
      />
    );
  }

  if (authority.status === "loading") {
    return <GlobalSearchSkeleton />;
  }

  if (authority.status !== "ready" || !hasReadableSurface) {
    return (
      <SearchBoundary
        title="Search is not available"
        detail="The current live tenant authority does not expose an Alert or Case read path. The API remains the authorization boundary."
      />
    );
  }

  return (
    <div className="content global-search-page">
      <section className="page-heading" aria-labelledby="global-search-title">
        <div>
          <p className="section-label">Tenant investigation</p>
          <h1 id="global-search-title">Global search</h1>
          <p>
            Search the authorized Alert and Case projections for the active
            tenant. Private or cross-tenant data is excluded before results
            reach this page.
          </p>
        </div>
        <Badge variant="outline">
          <Search aria-hidden="true" /> Server-side bounded search
        </Badge>
      </section>

      <form className="global-search-form" role="search" onSubmit={submit}>
        <label htmlFor="global-search-query">Search terms</label>
        <div>
          <Search aria-hidden="true" />
          <Input
            id="global-search-query"
            autoComplete="off"
            maxLength={maximumSearchLength}
            placeholder="Ticket number, title, or description…"
            value={draft}
            onChange={(event) => setDraft(event.target.value)}
          />
          <Button type="submit">Search tenant</Button>
        </div>
        <small>
          Query state is stored in the URL so an authorized view can be
          revisited without persisting result data in the browser.
        </small>
      </form>

      {committedQuery ? (
        <div className="global-search-results" aria-live="polite">
          {readableSurfaces.map((surface, index) =>
            surface.canRead ? (
              <SearchResultCard
                key={surface.kind}
                icon={surface.icon}
                kind={surface.kind}
                query={committedQuery}
                result={results[index]}
              />
            ) : null,
          )}
        </div>
      ) : (
        <Card className="global-search-prompt">
          <CardHeader>
            <CardTitle>Start with a bounded query</CardTitle>
            <CardDescription>
              Search is executed only after submission and never scans an
              in-browser cache of other queues.
            </CardDescription>
          </CardHeader>
        </Card>
      )}
    </div>
  );
}

interface SearchResultCardProps {
  icon: React.JSX.Element;
  kind: TicketKind;
  query: string;
  result:
    | {
        data: TicketPage | undefined;
        error: unknown;
        isError: boolean;
        isPending: boolean;
      }
    | undefined;
}

function SearchResultCard({
  icon,
  kind,
  query,
  result,
}: SearchResultCardProps): React.JSX.Element {
  const items = result?.data?.items ?? [];
  return (
    <Card className="global-search-result-card">
      <CardHeader>
        <div className="global-search-result-card__heading">
          <span aria-hidden="true">{icon}</span>
          <div>
            <CardTitle>{kindLabelPlural(kind)}</CardTitle>
            <CardDescription>
              {result?.isPending
                ? "Searching the authorized projection…"
                : `${items.length} result${items.length === 1 ? "" : "s"} in this bounded page`}
            </CardDescription>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        {result?.isPending ? <SearchResultSkeleton /> : null}
        {result?.isError ? (
          <FocusedError
            title={`${kindLabelPlural(kind)} search unavailable`}
            message={describeTicketingError(
              result.error,
              `The ${kindLabelPlural(kind).toLowerCase()} projection could not be searched.`,
            )}
          />
        ) : null}
        {!result?.isPending && !result?.isError && items.length === 0 ? (
          <div className="global-search-empty">
            <strong>No authorized matches</strong>
            <p>
              No {kindLabelPlural(kind).toLowerCase()} in the current projection
              matched “{query}”.
            </p>
          </div>
        ) : null}
        {items.length > 0 ? (
          <ol className="global-search-result-list">
            {items.map((item) => (
              <SearchResult key={item.id} kind={kind} item={item} />
            ))}
          </ol>
        ) : null}
        {result?.data?.nextCursor ? (
          <p className="global-search-result-card__bounded">
            More matches exist. Refine the query or open the full{" "}
            <Link
              to={`/${kind === "alert" ? "alerts" : "cases"}?search=${encodeURIComponent(query)}`}
            >
              {kindLabelPlural(kind).toLowerCase()} queue
            </Link>
            .
          </p>
        ) : null}
      </CardContent>
    </Card>
  );
}

function SearchResult({
  item,
  kind,
}: {
  item: TicketProjection;
  kind: TicketKind;
}): React.JSX.Element {
  return (
    <li>
      <Link to={`/${kind === "alert" ? "alerts" : "cases"}/${item.id}`}>
        <span>{ticketNumber(kind, item)}</span>
        <strong>{item.title}</strong>
        <small>
          {humanizeKey(item.workflow.stateKey)} · Updated{" "}
          <TenantInstant value={item.updatedAt} />
        </small>
      </Link>
    </li>
  );
}

function SearchBoundary({
  detail,
  title,
}: {
  detail: string;
  title: string;
}): React.JSX.Element {
  return (
    <div className="content content--narrow">
      <section className="page-heading" aria-labelledby="search-boundary-title">
        <p className="section-label">Tenant investigation</p>
        <h1 id="search-boundary-title">{title}</h1>
        <p>{detail}</p>
      </section>
      <Card>
        <CardHeader>
          <ShieldX aria-hidden="true" />
          <CardTitle>Deny-by-default boundary</CardTitle>
          <CardDescription>
            Search controls do not grant access and no request was sent without
            an eligible tenant context.
          </CardDescription>
        </CardHeader>
      </Card>
    </div>
  );
}

function GlobalSearchSkeleton(): React.JSX.Element {
  return (
    <div className="content global-search-page" aria-busy="true">
      <div
        className="ticket-list-skeleton"
        aria-label="Loading search authority"
      >
        {Array.from({ length: 4 }, (_, index) => (
          <span key={index} />
        ))}
      </div>
    </div>
  );
}

function SearchResultSkeleton(): React.JSX.Element {
  return (
    <div className="global-search-result-skeleton" aria-label="Searching">
      {Array.from({ length: 3 }, (_, index) => (
        <span key={index} />
      ))}
    </div>
  );
}

export function canonicalSearch(value: string | null): string {
  if (value === null) return "";
  return Array.from(value.trim()).slice(0, maximumSearchLength).join("");
}
