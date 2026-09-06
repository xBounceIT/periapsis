import { Button } from "@periapsis/ui/components/ui/button";
import { useQueries } from "@tanstack/react-query";
import {
  BellRing,
  BriefcaseBusiness,
  CircleDot,
  RadioTower,
  UserRoundCheck,
} from "lucide-react";
import { Link } from "react-router";

import { useSession } from "../auth/session-context";
import { useTenantAuthority } from "../auth/tenant-authority-context";
import {
  TicketingApiError,
  type TicketKind,
  type TicketPage,
  type TicketingApi,
} from "../lib/ticketing-api";
import { useTicketingApi } from "./ticketing-context";
import { hasAnyTicketPermission, humanizeKey } from "./ticketing-model";

const queueDescriptors = [
  {
    icon: UserRoundCheck,
    key: "assigned_to_me",
    label: "My queue",
    note: "Tickets explicitly assigned to you.",
  },
  {
    icon: RadioTower,
    key: "my_operator_teams",
    label: "Team queue",
    note: "Work visible through your live team assignments.",
  },
  {
    icon: CircleDot,
    key: "unassigned",
    label: "Unassigned",
    note: "New work waiting for an authorized owner.",
  },
] as const;

type OperatorQueue = (typeof queueDescriptors)[number]["key"];

interface OperatorQueueBoardProps {
  api: TicketingApi;
  canReadAlerts: boolean;
  canReadCases: boolean;
  tenantId: string | undefined;
}

export function OperatorDashboard(): React.JSX.Element {
  const api = useTicketingApi();
  const { session } = useSession();
  const authority = useTenantAuthority();

  return (
    <OperatorQueueBoard
      api={api}
      canReadAlerts={hasAnyTicketPermission(
        authority.hasPermission,
        "alert.read",
      )}
      canReadCases={hasAnyTicketPermission(
        authority.hasPermission,
        "case.read",
      )}
      tenantId={session.activeTenantId}
    />
  );
}

export function OperatorQueueBoard({
  api,
  canReadAlerts,
  canReadCases,
  tenantId,
}: OperatorQueueBoardProps): React.JSX.Element {
  const requests = queueDescriptors.flatMap((queue) =>
    (["alert", "case"] as const).map((kind) => ({ kind, queue: queue.key })),
  );
  const queries = useQueries({
    queries: requests.map(({ kind, queue }) => ({
      enabled:
        Boolean(tenantId) && (kind === "alert" ? canReadAlerts : canReadCases),
      queryFn: ({ signal }: { signal: AbortSignal }) =>
        api.listTickets(
          kind,
          tenantId!,
          { limit: 5, queue, sort: "updated_at_desc" },
          signal,
        ),
      queryKey: ["operator-dashboard", tenantId, kind, queue],
      staleTime: 15_000,
    })),
  });

  if (!tenantId) {
    return (
      <section
        className="operator-queue-empty"
        aria-labelledby="queue-board-title"
      >
        <p className="section-label">Live work queues</p>
        <h2 id="queue-board-title">Select a tenant to enter incident orbit.</h2>
        <p>
          Queue requests stay disabled until the session has an explicit tenant
          context.
        </p>
      </section>
    );
  }

  if (!canReadAlerts && !canReadCases) {
    return (
      <section
        className="operator-queue-empty"
        aria-labelledby="queue-board-title"
      >
        <p className="section-label">Live work queues</p>
        <h2 id="queue-board-title">No ticket inventory is delegated here.</h2>
        <p>
          The navigation and this board remain closed until live tenant
          authority grants a read capability.
        </p>
      </section>
    );
  }

  return (
    <section
      className="operator-queue-board"
      aria-labelledby="queue-board-title"
    >
      <div className="operator-queue-board__orbit" aria-hidden="true">
        <span />
      </div>
      <header className="operator-queue-board__header">
        <div>
          <p className="section-label">Live work queues</p>
          <h2 id="queue-board-title">Choose the next incident handoff.</h2>
        </div>
        <p>
          Each lane is a fresh, bounded server projection. Counts describe only
          the first five visible records and never widen your authority.
        </p>
      </header>

      <div className="operator-queue-board__lanes">
        {queueDescriptors.map((descriptor, laneIndex) => {
          const alertQuery = queries[laneIndex * 2];
          const caseQuery = queries[laneIndex * 2 + 1];
          const Icon = descriptor.icon;
          return (
            <article className="operator-queue-lane" key={descriptor.key}>
              <div className="operator-queue-lane__heading">
                <span aria-hidden="true">
                  <Icon />
                </span>
                <div>
                  <h3>{descriptor.label}</h3>
                  <p>{descriptor.note}</p>
                </div>
              </div>
              <QueueKindSummary
                enabled={canReadAlerts}
                kind="alert"
                page={alertQuery?.data}
                pending={alertQuery?.isPending ?? false}
                error={alertQuery?.error}
                queue={descriptor.key}
              />
              <QueueKindSummary
                enabled={canReadCases}
                kind="case"
                page={caseQuery?.data}
                pending={caseQuery?.isPending ?? false}
                error={caseQuery?.error}
                queue={descriptor.key}
              />
            </article>
          );
        })}
      </div>
    </section>
  );
}

function QueueKindSummary({
  enabled,
  error,
  kind,
  page,
  pending,
  queue,
}: {
  enabled: boolean;
  error: unknown;
  kind: TicketKind;
  page: TicketPage | undefined;
  pending: boolean;
  queue: OperatorQueue;
}): React.JSX.Element | null {
  if (!enabled) return null;
  const Icon = kind === "alert" ? BellRing : BriefcaseBusiness;
  const label = kind === "alert" ? "Alerts" : "Cases";
  const target = `/${label.toLowerCase()}?queue=${queue}`;
  const ready = !pending && !error;

  return (
    <div className="operator-queue-kind" data-kind={kind}>
      <QueueKindHeader
        Icon={Icon}
        label={label}
        page={page}
        pending={pending}
        queue={queue}
        ready={ready}
      />
      {error ? (
        <p className="operator-queue-kind__error" role="status">
          {error instanceof TicketingApiError && error.status === 403
            ? `Server denied ${label.toLowerCase()} access.`
            : `${label} are unavailable.`}
        </p>
      ) : null}
      {ready && page?.items.length === 0 ? (
        <p className="operator-queue-kind__empty">
          No visible {label.toLowerCase()}.
        </p>
      ) : null}
      {ready && page && page.items.length > 0 ? (
        <ul className="operator-queue-kind__preview">
          {page.items.slice(0, 2).map((ticket) => (
            <li key={ticket.id}>
              <Link to={`/${label.toLowerCase()}/${ticket.id}`}>
                <span>{ticketReference(kind, ticket)}</span>
                <strong>{ticket.title}</strong>
                <small>{humanizeKey(ticket.workflow.stateKey)}</small>
              </Link>
            </li>
          ))}
        </ul>
      ) : null}
      {ready ? (
        <Button asChild size="sm" variant="ghost">
          <Link to={target}>
            Open {descriptorLinkLabel(queue)} {label.toLowerCase()}
          </Link>
        </Button>
      ) : null}
    </div>
  );
}

function ticketReference(
  kind: TicketKind,
  ticket: TicketPage["items"][number],
): string {
  return kind === "alert" && "alertNumber" in ticket
    ? ticket.alertNumber
    : kind === "case" && "caseNumber" in ticket
      ? ticket.caseNumber
      : "Ticket";
}

function descriptorLinkLabel(queue: OperatorQueue): string {
  switch (queue) {
    case "assigned_to_me":
      return "my";
    case "my_operator_teams":
      return "team";
    case "unassigned":
      return "unassigned";
    default: {
      const unreachable: never = queue;
      return unreachable;
    }
  }
}

interface QueueKindHeaderProps {
  Icon: typeof BellRing;
  label: "Alerts" | "Cases";
  page: TicketPage | undefined;
  pending: boolean;
  queue: "assigned_to_me" | "my_operator_teams" | "unassigned";
  ready: boolean;
}

function QueueKindHeader({
  Icon,
  label,
  page,
  pending,
  queue,
  ready,
}: QueueKindHeaderProps): React.JSX.Element {
  return (
    <div className="operator-queue-kind__summary">
      <span>
        <Icon aria-hidden="true" /> {label}
      </span>
      {pending ? <small role="status">Loading…</small> : null}
      {ready && page ? (
        <strong aria-label={`${queue} ${label.toLowerCase()} visible`}>
          {page.items.length}
          {page.nextCursor ? "+" : ""}
        </strong>
      ) : null}
    </div>
  );
}
